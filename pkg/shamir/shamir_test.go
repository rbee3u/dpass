package shamir_test

import (
	"bytes"
	"iter"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/shamir"
)

func TestSplitAndCombine(t *testing.T) {
	longSecret := bytes.Repeat([]byte{0xab}, 256)

	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
	}{
		{name: "ascii string", secret: []byte("test"), parts: 9, threshold: 4},
		{name: "empty secret", secret: []byte{}, parts: 3, threshold: 2},
		{name: "single byte", secret: []byte{0xff}, parts: 5, threshold: 3},
		{name: "all zeros", secret: []byte{0, 0, 0, 0}, parts: 5, threshold: 3},
		{name: "256 bytes", secret: longSecret, parts: 7, threshold: 4},
		{name: "threshold equals parts", secret: []byte("edge"), parts: 5, threshold: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := shamir.Split(tt.secret, tt.parts, tt.threshold)
			require.NoError(t, err)
			require.Len(t, shares, tt.parts)

			for i, share := range shares {
				require.Equal(t, uint8(i+1), share[len(share)-1])
			}

			for k := tt.threshold; k <= tt.parts; k++ {
				for group := range combinations(shares, k) {
					recovered, err := shamir.Combine(group)
					require.NoError(t, err)
					require.Equal(t, tt.secret, recovered)
				}
			}
		})
	}
}

func TestSplitValidation(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
		assertErr func(*testing.T, error)
	}{
		{
			name:      "parts less than threshold",
			secret:    []byte("test"),
			parts:     2,
			threshold: 3,
			assertErr: func(t *testing.T, err error) {
				var target shamir.PartsBelowThresholdError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Parts)
				require.Equal(t, 3, target.Threshold)
				require.Equal(
					t,
					"shamir: invalid parts (got 2, must be >= threshold 3)",
					err.Error(),
				)
			},
		},
		{
			name:      "parts greater than limit",
			secret:    []byte("test"),
			parts:     1000,
			threshold: 3,
			assertErr: func(t *testing.T, err error) {
				var target shamir.PartsOverLimitError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1000, target.Parts)
				require.Equal(t, 255, target.Max)
				require.Equal(
					t,
					"shamir: invalid parts (got 1000, must be <= 255)",
					err.Error(),
				)
			},
		},
		{
			name:      "threshold too small",
			secret:    []byte("test"),
			parts:     10,
			threshold: 1,
			assertErr: func(t *testing.T, err error) {
				var target shamir.ThresholdTooSmallError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Threshold)
				require.Equal(t, 2, target.Min)
				require.Equal(
					t,
					"shamir: invalid threshold (got 1, must be >= 2)",
					err.Error(),
				)
			},
		},
		{
			name:      "zero parts",
			secret:    []byte("test"),
			parts:     0,
			threshold: 0,
			assertErr: func(t *testing.T, err error) {
				var target shamir.ThresholdTooSmallError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Threshold)
				require.Equal(t, 2, target.Min)
				require.Equal(
					t,
					"shamir: invalid threshold (got 0, must be >= 2)",
					err.Error(),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := shamir.Split(tt.secret, tt.parts, tt.threshold)
			require.Error(t, err)
			require.Nil(t, shares)
			tt.assertErr(t, err)
		})
	}
}

func TestCombineValidation(t *testing.T) {
	shares, err := shamir.Split([]byte("test"), 5, 4)
	require.NoError(t, err)

	withXCoordinate := func(share []byte, x byte) []byte {
		clone := append([]byte(nil), share...)
		clone[len(clone)-1] = x
		return clone
	}

	tests := []struct {
		name      string
		shares    [][]byte
		assertErr func(*testing.T, error)
	}{
		{
			name:   "no shares",
			shares: nil,
			assertErr: func(t *testing.T, err error) {
				var target shamir.SharesTooFewError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Count)
				require.Equal(t, 2, target.Min)
				require.Equal(
					t,
					"shamir: insufficient shares (got 0, must be >= 2)",
					err.Error(),
				)
			},
		},
		{
			name:   "single share",
			shares: [][]byte{shares[0]},
			assertErr: func(t *testing.T, err error) {
				var target shamir.SharesTooFewError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Count)
				require.Equal(t, 2, target.Min)
				require.Equal(
					t,
					"shamir: insufficient shares (got 1, must be >= 2)",
					err.Error(),
				)
			},
		},
		{
			name:   "inconsistent lengths",
			shares: [][]byte{[]byte("foo"), []byte("ba")},
			assertErr: func(t *testing.T, err error) {
				var target shamir.ShareLengthMismatchError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
				require.Equal(t, 2, target.Length)
				require.Equal(t, 3, target.Want)
				require.Equal(
					t,
					"shamir: share 1: inconsistent length (got 2, want 3)",
					err.Error(),
				)
			},
		},
		{
			name:   "empty share",
			shares: [][]byte{{}, {}},
			assertErr: func(t *testing.T, err error) {
				var target shamir.ShareTooShortError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Index)
				require.Equal(t, 0, target.Length)
				require.Equal(t, 1, target.Min)
				require.Equal(
					t,
					"shamir: share 0: invalid length (got 0, must be >= 1)",
					err.Error(),
				)
			},
		},
		{
			name: "duplicate x-coordinates",
			shares: [][]byte{
				shares[0],
				withXCoordinate(shares[1], shares[0][len(shares[0])-1]),
			},
			assertErr: func(t *testing.T, err error) {
				var target shamir.ShareXDuplicateError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
				require.Equal(t, 0, target.PrevIndex)
				require.Equal(t, shares[0][len(shares[0])-1], target.X)
				require.Equal(
					t,
					"shamir: share 1: x-coordinate 1 duplicates share 0",
					err.Error(),
				)
			},
		},
		{
			name:   "zero x-coordinate",
			shares: [][]byte{withXCoordinate(shares[0], 0), shares[1]},
			assertErr: func(t *testing.T, err error) {
				var target shamir.ShareXZeroError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Index)
				require.Equal(
					t,
					"shamir: share 0: x-coordinate 0 is reserved",
					err.Error(),
				)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := shamir.Combine(tt.shares)
			require.Error(t, err)
			require.Nil(t, secret)
			tt.assertErr(t, err)
		})
	}
}

func TestPolyGenerate(t *testing.T) {
	coefficients := shamir.PolyGenerate(2, 42)
	require.Len(t, coefficients, 3)
	require.Equal(t, uint8(42), coefficients[0])
	require.NotZero(t, coefficients[2])
}

func TestPolyEvaluate(t *testing.T) {
	coefficients := []uint8{42, 17, 99}
	require.Equal(t, uint8(42), shamir.PolyEvaluate(coefficients, 0))
	require.Equal(t, uint8(88), shamir.PolyEvaluate(coefficients, 1))
	require.Equal(t, uint8(159), shamir.PolyEvaluate(coefficients, 2))
	require.Equal(t, uint8(195), shamir.PolyEvaluate(coefficients, 7))
	require.Equal(t, uint8(115), shamir.PolyEvaluate(coefficients, 255))
}

func TestPolyWeights(t *testing.T) {
	xCoords := []uint8{1, 2, 7}
	require.Equal(t, []uint8{165, 99, 199}, shamir.PolyWeights(xCoords, 0))
	require.Equal(t, []uint8{1, 0, 0}, shamir.PolyWeights(xCoords, 1))
	require.Equal(t, []uint8{0, 1, 0}, shamir.PolyWeights(xCoords, 2))
	require.Equal(t, []uint8{0, 0, 1}, shamir.PolyWeights(xCoords, 7))
	require.Equal(t, []uint8{138, 147, 24}, shamir.PolyWeights(xCoords, 255))
}

func TestFieldAdd(t *testing.T) {
	require.Equal(t, uint8(0), shamir.FieldAdd(16, 16))
	require.Equal(t, uint8(7), shamir.FieldAdd(3, 4))
	require.Equal(t, uint8(3), shamir.FieldAdd(3, 0))
}

func TestFieldMul(t *testing.T) {
	require.Equal(t, uint8(0), shamir.FieldMul(3, 0))
	require.Equal(t, uint8(0), shamir.FieldMul(0, 3))
	require.Equal(t, uint8(3), shamir.FieldMul(3, 1))
	require.Equal(t, uint8(3), shamir.FieldMul(1, 3))
	require.Equal(t, uint8(9), shamir.FieldMul(3, 7))
	require.Equal(t, uint8(9), shamir.FieldMul(7, 3))
}

func TestFieldDiv(t *testing.T) {
	require.Equal(t, uint8(0), shamir.FieldDiv(0, 3))
	require.Equal(t, uint8(1), shamir.FieldDiv(3, 3))
	require.Equal(t, uint8(7), shamir.FieldDiv(9, 3))
}

func TestFieldInv(t *testing.T) {
	for x := uint8(1); x != 0; x++ {
		require.Equalf(t, uint8(1), shamir.FieldMul(x, shamir.FieldInv(x)),
			"fieldMul(%d, fieldInv(%d)) != 1", x, x)
	}
}

// combinations yields all k-element subsets of s in lexicographic order.
func combinations(s [][]byte, k int) iter.Seq[[][]byte] {
	return func(yield func([][]byte) bool) {
		n := len(s)
		if k < 0 || k > n {
			return
		}

		indices := make([]int, k)
		for i := range indices {
			indices[i] = i
		}

		group := make([][]byte, k)
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
