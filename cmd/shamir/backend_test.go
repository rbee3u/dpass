package shamir

import (
	"bytes"
	"encoding/pem"
	"iter"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/shamir"
)

func TestBackend(t *testing.T) {
	t.Run("split emits shamir blocks and combine recovers all combinations", func(t *testing.T) {
		secret := []byte("To be, or not to be, that is the question.")
		sb := splitBackendDefault()
		sb.parts = 5
		sb.threshold = 3
		blocks, err := sb.split(secret)
		require.NoError(t, err)
		require.Len(t, blocks, sb.parts)
		for i, block := range blocks {
			require.Equal(t, "SHAMIR", block.Type)
			require.Equal(t, "5", block.Headers["N"])
			require.Equal(t, "3", block.Headers["M"])
			require.Equal(t, strconv.Itoa(i), block.Headers["I"])
			require.Len(t, block.Bytes, len(secret)+1)
		}
		cb := combineBackendDefault()
		for k := sb.threshold; k <= sb.parts; k++ {
			for group := range combinations(blocks, k) {
				recovered, err := cb.combine(group)
				require.NoError(t, err)
				require.Equal(t, secret, recovered)
			}
		}
	})
	t.Run("published fixture shares all combinations", func(t *testing.T) {
		cb := combineBackendDefault()
		want := []byte("To be, or not to be, that is the question.")
		data := []byte(`-----BEGIN SHAMIR-----
I: 0
M: 4
N: 9

Dk3CZ2JyqWolAndv6mR/3wKTfV8DyZklxG6DhbVMCxNHy1mF2Zc2OUkIqg==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 1
M: 4
N: 9

Smmg52twM1VredYIRNZV6zi//2ker0aPVodffiH41n1/u8bY65Y7u60xag==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 2
M: 4
N: 9

YMbVk0audTbtH6LMlowsKBGSRp+ZnHFhDEg/vFcH5lWHOMtGJErR/kT5zA==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 3
M: 4
N: 9

hbjVzD0jh0XEENKPOu4bkeAqjUHgK4SJWqETXVN08L8K1/VbRYIqapnVjA==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 4
M: 4
N: 9

FaaWqcffvsZqyYMEIRO62xDetR4+ZsnHRzOMlNIYXCQ81YQvj9OzPWv3OA==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 5
M: 4
N: 9

K1T5ZHs4Id9DUU6Y2CSUHZdScPe+y4xKbMvJLpizUVuthpMOF0aZTQNgIw==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 6
M: 4
N: 9

vRDD4CSccI84z02dublRBZUsNLQ46w+H6hYIMMSHsd3Po1NVb3NHk9Ft5A==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 7
M: 4
N: 9

Zfev+F6BGDQSaSFoQiP48o+8DsVZV64eX0ceQzqmcJouqbGaajchgmMEuQ==
-----END SHAMIR-----
-----BEGIN SHAMIR-----
I: 8
M: 4
N: 9

1N3xLp2dDR1NlNvVSUPBht5Z/UYtu5ZhtOrvzc+ljz1a7VorCwfCZ7b3EQ==
-----END SHAMIR-----`)
		var blocks []*pem.Block
		for len(data) != 0 {
			block, rest := pem.Decode(data)
			require.NotNil(t, block)
			blocks = append(blocks, block)
			data = bytes.TrimSpace(rest)
		}
		for k := 4; k <= 9; k++ {
			for group := range combinations(blocks, k) {
				secret, err := cb.combine(group)
				require.NoError(t, err)
				require.Equal(t, want, secret)
			}
		}
	})
}

func TestSplitBackendWrapsSplitError(t *testing.T) {
	sb := splitBackendDefault()
	sb.parts = 9
	sb.threshold = 1
	blocks, err := sb.split([]byte("test"))
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to split secret")
	var target shamir.SplitConstraintError
	require.ErrorAs(t, err, &target)
	require.Equal(t, 9, target.Parts)
	require.Equal(t, 1, target.Threshold)
	require.Nil(t, blocks)
}

func TestCombineBackendErrors(t *testing.T) {
	genBlocks := func(t *testing.T, parts, threshold int) []*pem.Block {
		t.Helper()
		sb := splitBackendDefault()
		sb.parts = parts
		sb.threshold = threshold
		blocks, err := sb.split([]byte("test"))
		require.NoError(t, err)
		return blocks
	}
	tests := []struct {
		name       string
		blocks     func(*testing.T) []*pem.Block
		requireErr func(*testing.T, error)
	}{
		{
			name: "no shares",
			blocks: func(t *testing.T) []*pem.Block {
				return nil
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errNoSharesProvided)
			},
		},
		{
			name: "unexpected block type",
			blocks: func(t *testing.T) []*pem.Block {
				blocks := genBlocks(t, 3, 2)
				blocks[0].Type = "CERTIFICATE"
				return blocks
			},
			requireErr: func(t *testing.T, err error) {
				var target unexpectedBlockTypeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Pos)
				require.Equal(t, "CERTIFICATE", target.Got)
				require.Equal(t, "SHAMIR", target.Want)
			},
		},
		{
			name: "missing header",
			blocks: func(t *testing.T) []*pem.Block {
				blocks := genBlocks(t, 3, 2)
				delete(blocks[0].Headers, "M")
				return blocks
			},
			requireErr: func(t *testing.T, err error) {
				var target missingHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Pos)
				require.Equal(t, "M", target.Key)
			},
		},
		{
			name: "malformed header",
			blocks: func(t *testing.T) []*pem.Block {
				blocks := genBlocks(t, 3, 2)
				blocks[0].Headers["M"] = "bad"
				return blocks
			},
			requireErr: func(t *testing.T, err error) {
				var target malformedHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Pos)
				require.Equal(t, "M", target.Key)
			},
		},
		{
			name: "invalid header constraints",
			blocks: func(t *testing.T) []*pem.Block {
				blocks := genBlocks(t, 4, 2)
				blocks[0].Headers["N"] = "1"
				blocks[0].Headers["M"] = "3"
				blocks[0].Headers["I"] = "1"
				return blocks
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Pos)
				require.Equal(t, 1, target.Parts)
				require.Equal(t, 3, target.Threshold)
				require.Equal(t, 1, target.Index)
			},
		},
		{
			name: "inconsistent threshold header",
			blocks: func(t *testing.T) []*pem.Block {
				blocks := genBlocks(t, 4, 2)
				blocks[1].Headers["M"] = "3"
				return blocks
			},
			requireErr: func(t *testing.T, err error) {
				var target inconsistentHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Pos)
				require.Equal(t, "M", target.Key)
				require.Equal(t, 3, target.Got)
				require.Equal(t, 2, target.Want)
			},
		},
		{
			name: "insufficient shares",
			blocks: func(t *testing.T) []*pem.Block {
				blocks := genBlocks(t, 4, 3)
				return blocks[:2]
			},
			requireErr: func(t *testing.T, err error) {
				var target insufficientSharesError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Got)
				require.Equal(t, 3, target.Need)
			},
		},
		{
			name: "duplicate header",
			blocks: func(t *testing.T) []*pem.Block {
				blocks := genBlocks(t, 4, 2)
				blocks[1].Headers["I"] = blocks[0].Headers["I"]
				return blocks
			},
			requireErr: func(t *testing.T, err error) {
				var target duplicateHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Pos)
				require.Equal(t, 0, target.PrevPos)
				require.Equal(t, "I", target.Key)
				require.Equal(t, 0, target.Value)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := combineBackendDefault()
			secret, err := cb.combine(tt.blocks(t))
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, secret)
		})
	}
}

func combinations(s []*pem.Block, k int) iter.Seq[[]*pem.Block] {
	return func(yield func([]*pem.Block) bool) {
		if k < 0 || k > len(s) {
			return
		}
		indices := make([]int, k)
		for i := range indices {
			indices[i] = i
		}
		group := make([]*pem.Block, k)
		for {
			for i := range indices {
				group[i] = s[indices[i]]
			}
			if !yield(group) {
				return
			}
			i := k - 1
			for i >= 0 && indices[i] == i+len(s)-k {
				i--
			}
			if i < 0 {
				return
			}
			for indices[i]++; i+1 < k; i++ {
				indices[i+1] = indices[i] + 1
			}
		}
	}
}
