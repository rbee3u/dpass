package shamir

import (
	"encoding/pem"
	"iter"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/shamir"
)

func TestBackend(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
	}{
		{
			name:      "ascii secret",
			secret:    []byte("To be, or not to be, that is the question."),
			parts:     9,
			threshold: 4,
		},
		{
			name:      "empty secret",
			secret:    []byte{},
			parts:     3,
			threshold: 2,
		},
		{
			name:      "threshold equals parts",
			secret:    []byte("edge"),
			parts:     5,
			threshold: 5,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := splitBackendDefault()
			sb.parts = tt.parts
			sb.threshold = tt.threshold
			blocks, err := sb.split(tt.secret)
			require.NoError(t, err)
			require.Len(t, blocks, tt.parts)
			cb := combineBackendDefault()
			for k := tt.threshold; k <= tt.parts; k++ {
				for group := range combinations(blocks, k) {
					secret, err := cb.combine(group)
					require.NoError(t, err)
					require.Equal(t, tt.secret, secret)
				}
			}
		})
	}
	t.Run("published fixture shares", func(t *testing.T) {
		cb := combineBackendDefault()
		want := []byte("To be, or not to be, that is the question.")
		fixtureBlocks := func(t *testing.T) []*pem.Block {
			t.Helper()
			fixtures := []string{
				`
-----BEGIN SHAMIR-----
I: 0
M: 4
N: 9

Dk3CZ2JyqWolAndv6mR/3wKTfV8DyZklxG6DhbVMCxNHy1mF2Zc2OUkIqg==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 1
M: 4
N: 9

Smmg52twM1VredYIRNZV6zi//2ker0aPVodffiH41n1/u8bY65Y7u60xag==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 2
M: 4
N: 9

YMbVk0audTbtH6LMlowsKBGSRp+ZnHFhDEg/vFcH5lWHOMtGJErR/kT5zA==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 3
M: 4
N: 9

hbjVzD0jh0XEENKPOu4bkeAqjUHgK4SJWqETXVN08L8K1/VbRYIqapnVjA==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 4
M: 4
N: 9

FaaWqcffvsZqyYMEIRO62xDetR4+ZsnHRzOMlNIYXCQ81YQvj9OzPWv3OA==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 5
M: 4
N: 9

K1T5ZHs4Id9DUU6Y2CSUHZdScPe+y4xKbMvJLpizUVuthpMOF0aZTQNgIw==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 6
M: 4
N: 9

vRDD4CSccI84z02dublRBZUsNLQ46w+H6hYIMMSHsd3Po1NVb3NHk9Ft5A==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 7
M: 4
N: 9

Zfev+F6BGDQSaSFoQiP48o+8DsVZV64eX0ceQzqmcJouqbGaajchgmMEuQ==
-----END SHAMIR-----
`,
				`
-----BEGIN SHAMIR-----
I: 8
M: 4
N: 9

1N3xLp2dDR1NlNvVSUPBht5Z/UYtu5ZhtOrvzc+ljz1a7VorCwfCZ7b3EQ==
-----END SHAMIR-----
`,
			}
			blocks := make([]*pem.Block, 0, len(fixtures))
			for _, fixture := range fixtures {
				block, _ := pem.Decode([]byte(fixture))
				require.NotNil(t, block)
				blocks = append(blocks, block)
			}
			return blocks
		}
		for k := 4; k <= 9; k++ {
			for group := range combinations(fixtureBlocks(t), k) {
				secret, err := cb.combine(group)
				require.NoError(t, err)
				require.Equal(t, want, secret)
			}
		}
	})
}

func TestSplitBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		secret     []byte
		parts      int
		threshold  int
		requireErr func(*testing.T, error)
	}{
		{
			name:      "threshold too small",
			secret:    []byte("test"),
			parts:     3,
			threshold: 1,
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.SplitConstraintError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 3, target.Parts)
				require.Equal(t, 1, target.Threshold)
			},
		},
		{
			name:      "threshold greater than parts",
			secret:    []byte("test"),
			parts:     2,
			threshold: 3,
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.SplitConstraintError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Parts)
				require.Equal(t, 3, target.Threshold)
			},
		},
		{
			name:      "parts too large",
			secret:    []byte("test"),
			parts:     256,
			threshold: 3,
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.SplitConstraintError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 256, target.Parts)
				require.Equal(t, 3, target.Threshold)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := splitBackendDefault()
			sb.parts = tt.parts
			sb.threshold = tt.threshold
			blocks, err := sb.split(tt.secret)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, blocks)
		})
	}
}

func TestCombineBackendErrors(t *testing.T) {
	splitBlocks := func(t *testing.T, parts, threshold int) []*pem.Block {
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
		run        func(*testing.T) ([]byte, error)
		requireErr func(*testing.T, error)
	}{
		{
			name: "no shares",
			run: func(t *testing.T) ([]byte, error) {
				return combineBackendDefault().combine(nil)
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errNoSharesProvided)
			},
		},
		{
			name: "insufficient shares",
			run: func(t *testing.T) ([]byte, error) {
				return combineBackendDefault().combine(splitBlocks(t, 4, 3)[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target insufficientSharesError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Got)
				require.Equal(t, 3, target.Need)
			},
		},
		{
			name: "missing threshold header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 3, 2)
				delete(blocks[0].Headers, "M")
				return combineBackendDefault().combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target missingHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Position)
				require.Equal(t, "M", target.Key)
			},
		},
		{
			name: "invalid parts header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["N"] = "1"
				return combineBackendDefault().combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Position)
				require.Equal(t, "N", target.Key)
				require.Equal(t, 1, target.Value)
			},
		},
		{
			name: "inconsistent threshold header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["M"] = "3"
				return combineBackendDefault().combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target inconsistentHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Position)
				require.Equal(t, "M", target.Key)
				require.Equal(t, 3, target.Got)
				require.Equal(t, 2, target.Want)
			},
		},
		{
			name: "invalid share index header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["I"] = "4"
				return combineBackendDefault().combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Position)
				require.Equal(t, "I", target.Key)
				require.Equal(t, 4, target.Value)
			},
		},
		{
			name: "duplicate share index header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["I"] = blocks[0].Headers["I"]
				return combineBackendDefault().combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target duplicateHeaderValueError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Position)
				require.Equal(t, 0, target.Previous)
				require.Equal(t, "I", target.Key)
				require.Equal(t, 0, target.Value)
			},
		},
		{
			name: "unexpected block type",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Type = "CERTIFICATE"
				return combineBackendDefault().combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target unexpectedBlockTypeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Position)
				require.Equal(t, "CERTIFICATE", target.Got)
				require.Equal(t, shareType, target.Want)
			},
		},
		{
			name: "too many shares",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 3, 2)
				return combineBackendDefault().combine(append(blocks, blocks[0]))
			},
			requireErr: func(t *testing.T, err error) {
				var target tooManySharesError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 4, target.Got)
				require.Equal(t, 3, target.Max)
			},
		},
		{
			name: "empty share body",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 3, 2)
				blocks[0].Bytes = nil
				return combineBackendDefault().combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				var target emptyShareBodyError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Position)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := tt.run(t)
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
