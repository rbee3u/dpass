package shamir

import (
	"bytes"
	"encoding/pem"
	"iter"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/shamir"
	"github.com/rbee3u/dpass/pkg/testx"
)

func TestBackend(t *testing.T) {
	t.Run("split emits shamir blocks and combine recovers all combinations", func(t *testing.T) {
		secret := []byte("To be, or not to be, that is the question.")
		sb := &splitBackend{parts: 5, threshold: 3}
		sb.reader = testx.NewReader(secret, nil)
		sbWriter := testx.NewWriter(nil)
		sb.writer = sbWriter
		require.NoError(t, sb.runE(nil, nil))
		blocks := decodeBlocks(t, sbWriter.Bytes())
		require.Len(t, blocks, sb.parts)
		for index, block := range blocks {
			require.Equal(t, "SHAMIR", block.Type)
			require.Equal(t, "5", block.Headers["N"])
			require.Equal(t, "3", block.Headers["M"])
			require.Equal(t, strconv.Itoa(index), block.Headers["I"])
			require.Len(t, block.Bytes, len(secret)+1)
		}
		for k := sb.threshold; k <= sb.parts; k++ {
			for group := range combinations(blocks, k) {
				cb := &combineBackend{}
				cb.reader = testx.NewReader(encodeBlocks(group), nil)
				cbWriter := testx.NewWriter(nil)
				cb.writer = cbWriter
				require.NoError(t, cb.runE(nil, nil))
				testx.EqualSlice(t, secret, cbWriter.Bytes())
			}
		}
	})
	t.Run("published fixture shares all combinations", func(t *testing.T) {
		secret := []byte("To be, or not to be, that is the question.")
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
		blocks := decodeBlocks(t, data)
		for k := 4; k <= 9; k++ {
			for group := range combinations(blocks, k) {
				cb := &combineBackend{}
				cb.reader = testx.NewReader(encodeBlocks(group), nil)
				cbWriter := testx.NewWriter(nil)
				cb.writer = cbWriter
				require.NoError(t, cb.runE(nil, nil))
				testx.EqualSlice(t, secret, cbWriter.Bytes())
			}
		}
	})
}

func TestSplitBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		parts      int
		threshold  int
		reader     *testx.Reader
		writer     *testx.Writer
		requireErr func(*testing.T, error)
	}{
		{
			name:      "wraps split error",
			parts:     9,
			threshold: 1,
			reader:    testx.NewReader([]byte("test"), nil),
			writer:    testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to split secret")
				var target shamir.SplitConstraintError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 9, target.Parts)
				require.Equal(t, 1, target.Threshold)
			},
		},
		{
			name:      "reader read failure",
			parts:     3,
			threshold: 2,
			reader:    testx.NewReader(nil, testx.ErrReadFailure),
			writer:    testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read secret")
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
		{
			name:      "writer write failure",
			parts:     3,
			threshold: 2,
			reader:    testx.NewReader([]byte("test"), nil),
			writer:    testx.NewWriter(testx.ErrWriteFailure),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to write share 0")
				require.ErrorIs(t, err, testx.ErrWriteFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := &splitBackend{parts: tt.parts, threshold: tt.threshold}
			sb.reader, sb.writer = tt.reader, tt.writer
			tt.requireErr(t, sb.runE(nil, nil))
		})
	}
}

func TestCombineBackendErrors(t *testing.T) {
	genBlocks := func(t *testing.T, parts, threshold int) []*pem.Block {
		t.Helper()
		sb := &splitBackend{parts: parts, threshold: threshold}
		sb.reader = testx.NewReader([]byte("test"), nil)
		var sbWriter bytes.Buffer
		sb.writer = &sbWriter
		require.NoError(t, sb.runE(nil, nil))
		return decodeBlocks(t, sbWriter.Bytes())
	}
	tests := []struct {
		name       string
		reader     func(*testing.T) *testx.Reader
		writer     *testx.Writer
		requireErr func(*testing.T, error)
	}{
		{
			name: "malformed PEM input",
			reader: func(t *testing.T) *testx.Reader {
				return testx.NewReader([]byte("not a pem block"), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errMalformedPEMInput)
			},
		},
		{
			name: "no shares",
			reader: func(t *testing.T) *testx.Reader {
				return testx.NewReader(nil, nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, errNoSharesProvided)
			},
		},
		{
			name: "unexpected block type",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 3, 2)
				blocks[0].Type = "CERTIFICATE"
				return testx.NewReader(encodeBlocks(blocks), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target unexpectedBlockTypeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.pos)
				require.Equal(t, "CERTIFICATE", target.got)
				require.Equal(t, "SHAMIR", target.want)
			},
		},
		{
			name: "missing header",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 3, 2)
				delete(blocks[0].Headers, "M")
				return testx.NewReader(encodeBlocks(blocks), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target missingHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.pos)
				require.Equal(t, "M", target.key)
			},
		},
		{
			name: "malformed header",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 3, 2)
				blocks[0].Headers["M"] = "bad"
				return testx.NewReader(encodeBlocks(blocks), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target malformedHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.pos)
				require.Equal(t, "M", target.key)
			},
		},
		{
			name: "invalid header constraints",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 4, 2)
				blocks[0].Headers["N"] = "1"
				blocks[0].Headers["M"] = "3"
				blocks[0].Headers["I"] = "1"
				return testx.NewReader(encodeBlocks(blocks), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target invalidHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.pos)
				require.Equal(t, 1, target.parts)
				require.Equal(t, 3, target.threshold)
				require.Equal(t, 1, target.index)
			},
		},
		{
			name: "inconsistent threshold header",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 4, 2)
				blocks[1].Headers["M"] = "3"
				return testx.NewReader(encodeBlocks(blocks), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target inconsistentHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.pos)
				require.Equal(t, "M", target.key)
				require.Equal(t, 3, target.got)
				require.Equal(t, 2, target.want)
			},
		},
		{
			name: "insufficient shares",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 4, 3)
				return testx.NewReader(encodeBlocks(blocks[:2]), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target insufficientSharesError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.got)
				require.Equal(t, 3, target.min)
			},
		},
		{
			name: "duplicate header",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 4, 2)
				blocks[1].Headers["I"] = blocks[0].Headers["I"]
				return testx.NewReader(encodeBlocks(blocks), nil)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target duplicateHeaderError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.pos)
				require.Equal(t, 0, target.prevPos)
				require.Equal(t, "I", target.key)
				require.Equal(t, 0, target.value)
			},
		},
		{
			name: "reader read failure",
			reader: func(_ *testing.T) *testx.Reader {
				return testx.NewReader(nil, testx.ErrReadFailure)
			},
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read shares")
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
		{
			name: "writer write failure",
			reader: func(t *testing.T) *testx.Reader {
				blocks := genBlocks(t, 3, 2)
				return testx.NewReader(encodeBlocks(blocks), nil)
			},
			writer: testx.NewWriter(testx.ErrWriteFailure),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to write secret")
				require.ErrorIs(t, err, testx.ErrWriteFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cb := &combineBackend{}
			cb.reader, cb.writer = tt.reader(t), tt.writer
			tt.requireErr(t, cb.runE(nil, nil))
		})
	}
}

func decodeBlocks(t *testing.T, data []byte) []*pem.Block {
	t.Helper()
	data = bytes.TrimSpace(data)
	var blocks []*pem.Block
	for len(data) != 0 {
		block, rest := pem.Decode(data)
		require.NotNil(t, block)
		blocks = append(blocks, block)
		data = bytes.TrimSpace(rest)
	}
	return blocks
}

func encodeBlocks(blocks []*pem.Block) []byte {
	var buf bytes.Buffer
	for _, block := range blocks {
		_ = pem.Encode(&buf, block)
	}
	return buf.Bytes()
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
