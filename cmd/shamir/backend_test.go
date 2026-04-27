package shamir

import (
	"encoding/pem"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/shamir"
)

const fixtureSecret = "To be, or not to be, that is the question."

func TestSplitBackend(t *testing.T) {
	secret := []byte(fixtureSecret)

	t.Run("shares recombine to secret", func(t *testing.T) {
		requireAllCombinationsRecoverSecret(t, splitBlocks(t, 9, 4), 4, secret)
	})

	t.Run("runE writes pem to stdout", func(t *testing.T) {
		setStdinBytes(t, secret)
		data := captureStdoutBytes(t, func() {
			sb := splitBackendDefault()
			sb.parts = 4
			sb.threshold = 3
			require.NoError(t, sb.runE(nil, nil))
		})

		blocks, err := decodePEMBlocks(data)
		require.NoError(t, err)
		requireRecoveredSecret(t, blocks[:3], secret)
	})

	t.Run("runE writes pem to files", func(t *testing.T) {
		setStdinBytes(t, secret)
		prefix := filepath.Join(t.TempDir(), "share")

		sb := splitBackendDefault()
		sb.output = prefix
		sb.parts = 4
		sb.threshold = 3
		require.NoError(t, sb.runE(nil, nil))

		requireRecoveredSecret(t, readShareBlocks(t, prefix, 4, 3)[:3], secret)
	})
}

func TestCombineBackend(t *testing.T) {
	secret := []byte(fixtureSecret)

	t.Run("fixture shares recombine to secret", func(t *testing.T) {
		requireAllCombinationsRecoverSecret(t, combineFixtures(t), 4, secret)
	})

	t.Run("runE recovers secret from stdin", func(t *testing.T) {
		setStdinBytes(t, encodePEMBlocks(splitBlocks(t, 4, 3)[:3]))
		output := captureStdoutBytes(t, func() {
			cb := combineBackendDefault()
			require.NoError(t, cb.runE(nil, nil))
		})

		require.Equal(t, secret, output)
	})
}

func TestSplitBackendErrors(t *testing.T) {
	secret := []byte(fixtureSecret)
	tests := []struct {
		name       string
		run        func(*testing.T) error
		requireErr func(*testing.T, error)
	}{
		{
			name: "parts less than threshold",
			run: func(t *testing.T) error {
				sb := splitBackendDefault()
				sb.parts = 2
				sb.threshold = 3
				blocks, err := sb.split(secret)
				require.Nil(t, blocks)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.PartsBelowThresholdError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Parts)
				require.Equal(t, 3, target.Threshold)
			},
		},
		{
			name: "parts greater than limit",
			run: func(t *testing.T) error {
				sb := splitBackendDefault()
				sb.parts = 256
				sb.threshold = 3
				blocks, err := sb.split(secret)
				require.Nil(t, blocks)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.PartsOverLimitError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 256, target.Parts)
				require.Equal(t, shamir.MaxParts, target.Max)
			},
		},
		{
			name: "threshold too small",
			run: func(t *testing.T) error {
				sb := splitBackendDefault()
				sb.parts = 3
				sb.threshold = 1
				blocks, err := sb.split(secret)
				require.Nil(t, blocks)
				return err
			},
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
			err := tt.run(t)
			require.Error(t, err)
			tt.requireErr(t, err)
		})
	}
}

func TestCombineBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		run        func(*testing.T) error
		requireErr func(*testing.T, error)
	}{
		{
			name: "insufficient shares",
			run: func(t *testing.T) error {
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(splitBlocks(t, 9, 4)[:3])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "insufficient shares")
			},
		},
		{
			name: "missing threshold header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 3, 2)
				delete(blocks[0].Headers, "M")
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "missing M header")
			},
		},
		{
			name: "inconsistent threshold header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["M"] = "3"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "inconsistent M header")
			},
		},
		{
			name: "threshold header too small",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["M"] = "0"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid M header 0")
			},
		},
		{
			name: "threshold header negative",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["M"] = "-1"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid M header -1")
			},
		},
		{
			name: "threshold header too large",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["M"] = "256"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid M header 256")
			},
		},
		{
			name: "missing parts header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				delete(blocks[0].Headers, "N")
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "missing N header")
			},
		},
		{
			name: "invalid parts header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["N"] = "abc"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid N header")
			},
		},
		{
			name: "inconsistent parts header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["N"] = "3"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "inconsistent N header")
			},
		},
		{
			name: "parts header below threshold",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["N"] = "1"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid N header 1")
			},
		},
		{
			name: "missing share index header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				delete(blocks[0].Headers, "I")
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "missing I header")
			},
		},
		{
			name: "invalid share index header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["I"] = "abc"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid I header")
			},
		},
		{
			name: "share index header out of range",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Headers["I"] = "4"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "invalid I header 4")
			},
		},
		{
			name: "unexpected pem block type",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[0].Type = "CERTIFICATE"
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "unexpected block type")
			},
		},
		{
			name: "duplicate share index header",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 4, 2)
				blocks[1].Headers["I"] = blocks[0].Headers["I"]
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks[:2])
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "duplicate I header")
			},
		},
		{
			name: "too many shares for header parts",
			run: func(t *testing.T) error {
				blocks := splitBlocks(t, 3, 2)
				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(append(blocks, blocks[0]))
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "too many shares")
			},
		},
		{
			name: "trailing garbage",
			run: func(t *testing.T) error {
				raw := pem.EncodeToMemory(splitBlocks(t, 4, 2)[0])
				raw = append(raw, []byte("garbage")...)

				blocks, err := decodePEMBlocks(raw)
				if err != nil {
					return err
				}

				cb := combineBackendDefault()
				combinedSecret, err := cb.combine(blocks)
				require.Nil(t, combinedSecret)
				return err
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errMalformedPEMInput)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.run(t)
			require.Error(t, err)
			tt.requireErr(t, err)
		})
	}
}

func splitBlocks(t *testing.T, parts, threshold int) []*pem.Block {
	t.Helper()
	sb := splitBackendDefault()
	sb.parts = parts
	sb.threshold = threshold
	blocks, err := sb.split([]byte(fixtureSecret))
	require.NoError(t, err)
	return blocks
}

func setStdinBytes(t *testing.T, data []byte) {
	t.Helper()
	stdinReader, stdinWriter, err := os.Pipe()
	require.NoError(t, err)

	oldStdin := os.Stdin
	os.Stdin = stdinReader
	t.Cleanup(func() {
		os.Stdin = oldStdin
	})

	_, err = stdinWriter.Write(data)
	require.NoError(t, err)
	require.NoError(t, stdinWriter.Close())
}

func captureStdoutBytes(t *testing.T, run func()) []byte {
	t.Helper()
	stdoutReader, stdoutWriter, err := os.Pipe()
	require.NoError(t, err)

	oldStdout := os.Stdout
	os.Stdout = stdoutWriter
	t.Cleanup(func() {
		os.Stdout = oldStdout
	})

	run()

	require.NoError(t, stdoutWriter.Close())
	data, err := io.ReadAll(stdoutReader)
	require.NoError(t, err)
	require.NoError(t, stdoutReader.Close())

	return data
}

func requireAllCombinationsRecoverSecret(t *testing.T, blocks []*pem.Block, threshold int, want []byte) {
	t.Helper()
	for group := range combinations(blocks, threshold) {
		requireRecoveredSecret(t, group, want)
	}
}

func requireRecoveredSecret(t *testing.T, blocks []*pem.Block, want []byte) {
	t.Helper()
	cb := combineBackendDefault()
	combinedSecret, err := cb.combine(blocks)
	require.NoError(t, err)
	require.Equal(t, want, combinedSecret)
}

func readShareBlocks(t *testing.T, prefix string, parts, threshold int) []*pem.Block {
	t.Helper()
	blocks := make([]*pem.Block, 0, parts)
	for i := range parts {
		path := fmt.Sprintf("%s-%d-%d-%d.txt", prefix, parts, threshold, i)
		info, err := os.Stat(path)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(fileMode), info.Mode().Perm())

		data, err := os.ReadFile(path)
		require.NoError(t, err)

		block, rest := pem.Decode(data)
		require.NotNil(t, block)
		require.Empty(t, rest)
		blocks = append(blocks, block)
	}

	return blocks
}

func encodePEMBlocks(blocks []*pem.Block) []byte {
	var encoded []byte
	for _, block := range blocks {
		encoded = append(encoded, pem.EncodeToMemory(block)...)
	}

	return encoded
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
