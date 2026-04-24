package shamir

import (
	"encoding/pem"
	"iter"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/shamir"
)

func TestBackend(t *testing.T) {
	secret := []byte("To be, or not to be, that is the question.")
	tests := []struct {
		name   string
		blocks func(t *testing.T) []*pem.Block
	}{
		{
			name: "split output",
			blocks: func(t *testing.T) []*pem.Block {
				return splitBlocks(t, 9, 4)
			},
		},
		{
			name:   "fixture shares",
			blocks: combineFixtures,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks := tt.blocks(t)
			for group := range combinations(blocks, 4) {
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(group)
				require.NoError(t, err)
				require.Equal(t, secret, combinedSecret)
			}
		})
	}
}

func TestBackendSplitErrors(t *testing.T) {
	tests := []struct {
		name       string
		parts      int
		threshold  int
		requireErr func(*testing.T, error)
	}{
		{
			name:      "parts less than threshold",
			parts:     2,
			threshold: 3,
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.PartsBelowThresholdError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Parts)
				require.Equal(t, 3, target.Threshold)
			},
		},
		{
			name:      "parts greater than limit",
			parts:     256,
			threshold: 3,
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.PartsOverLimitError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 256, target.Parts)
				require.Equal(t, shamir.MaxParts, target.Max)
			},
		},
		{
			name:      "threshold too small",
			parts:     3,
			threshold: 1,
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.ThresholdTooSmallError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Threshold)
				require.Equal(t, shamir.MinThreshold, target.Min)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := splitBackendDefault()
			sb.parts = tt.parts
			sb.threshold = tt.threshold
			blocks, err := sb.split([]byte("To be, or not to be, that is the question."))
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, blocks)
		})
	}
}

func TestBackendCombineErrors(t *testing.T) {
	tests := []struct {
		name       string
		run        func(t *testing.T) ([]byte, error)
		requireErr func(*testing.T, error)
	}{
		{
			name: "insufficient shares",
			run: func(t *testing.T) ([]byte, error) {
				cb := combineBackendDefault()
				return cb.combine(splitBlocks(t, 9, 4)[:3])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "insufficient shares")
			},
		},
		{
			name: "missing threshold header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 3, 2)
				delete(blocks[0].Headers, "M")
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "missing M header")
			},
		},
		{
			name: "inconsistent threshold header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["M"] = "3"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "inconsistent M header")
			},
		},
		{
			name: "threshold header too small",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["M"] = "0"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid M header 0")
			},
		},
		{
			name: "threshold header negative",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["M"] = "-1"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid M header -1")
			},
		},
		{
			name: "threshold header too large",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["M"] = "256"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid M header 256")
			},
		},
		{
			name: "missing parts header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				delete(blocks[0].Headers, "N")
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "missing N header")
			},
		},
		{
			name: "invalid parts header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["N"] = "abc"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid N header")
			},
		},
		{
			name: "inconsistent parts header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["N"] = "3"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "inconsistent N header")
			},
		},
		{
			name: "parts header below threshold",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["N"] = "1"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid N header 1")
			},
		},
		{
			name: "missing share index header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				delete(blocks[0].Headers, "I")
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "missing I header")
			},
		},
		{
			name: "invalid share index header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["I"] = "abc"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid I header")
			},
		},
		{
			name: "share index header out of range",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["I"] = "4"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid I header 4")
			},
		},
		{
			name: "unexpected pem block type",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Type = "CERTIFICATE"
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "unexpected block type")
			},
		},
		{
			name: "duplicate share index header",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["I"] = blocks[0].Headers["I"]
				cb := combineBackendDefault()
				return cb.combine(blocks[:2])
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "duplicate I header")
			},
		},
		{
			name: "too many shares for header parts",
			run: func(t *testing.T) ([]byte, error) {
				blocks := splitBlocks(t, 3, 2)
				cb := combineBackendDefault()
				return cb.combine(append(blocks, blocks[0]))
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "too many shares")
			},
		},
		{
			name: "trailing garbage",
			run: func(t *testing.T) ([]byte, error) {
				raw := pem.EncodeToMemory(splitBlocks(t, 4, 2)[0])
				raw = append(raw, []byte("garbage")...)

				blocks, err := decodePEMBlocks(raw)
				if err != nil {
					return nil, err
				}

				cb := combineBackendDefault()
				return cb.combine(blocks)
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errMalformedPEMInput)
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

func splitBlocks(t *testing.T, parts, threshold int) []*pem.Block {
	t.Helper()
	sb := splitBackendDefault()
	sb.parts = parts
	sb.threshold = threshold
	blocks, err := sb.split([]byte("To be, or not to be, that is the question."))
	require.NoError(t, err)
	return blocks
}

func combineFixtures(t *testing.T) []*pem.Block {
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

// combinations yields all k-element subsets of s in lexicographic order.
func combinations(s []*pem.Block, k int) iter.Seq[[]*pem.Block] {
	return func(yield func([]*pem.Block) bool) {
		n := len(s)
		if k < 0 || k > n {
			return
		}

		indices := make([]int, k)
		for i := range indices {
			indices[i] = i
		}

		group := make([]*pem.Block, k)
		for {
			for i, idx := range indices {
				group[i] = s[idx]
			}

			if !yield(group) {
				return
			}

			i := k - 1
			for i >= 0 && indices[i] == i+n-k {
				i--
			}

			if i < 0 {
				return
			}

			indices[i]++
			for j := i + 1; j < k; j++ {
				indices[j] = indices[j-1] + 1
			}
		}
	}
}
