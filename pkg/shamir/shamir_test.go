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
		{
			name:      "ascii string",
			secret:    []byte("test"),
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
			name:      "single byte",
			secret:    []byte{0xff},
			parts:     5,
			threshold: 3,
		},
		{
			name:      "all zeros",
			secret:    []byte{0, 0, 0, 0},
			parts:     5,
			threshold: 3,
		},
		{
			name:      "256 bytes",
			secret:    longSecret,
			parts:     7,
			threshold: 4,
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

func TestSplitErrors(t *testing.T) {
	tests := []struct {
		name       string
		secret     []byte
		parts      int
		threshold  int
		requireErr func(*testing.T, error)
	}{
		{
			name:      "parts less than threshold",
			secret:    []byte("test"),
			parts:     2,
			threshold: 3,
			requireErr: func(t *testing.T, err error) {
				var target shamir.PartsBelowThresholdError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Parts)
				require.Equal(t, 3, target.Threshold)
			},
		},
		{
			name:      "parts greater than limit",
			secret:    []byte("test"),
			parts:     1000,
			threshold: 3,
			requireErr: func(t *testing.T, err error) {
				var target shamir.PartsOverLimitError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1000, target.Parts)
				require.Equal(t, 255, target.Max)
			},
		},
		{
			name:      "threshold too small",
			secret:    []byte("test"),
			parts:     10,
			threshold: 1,
			requireErr: func(t *testing.T, err error) {
				var target shamir.ThresholdTooSmallError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Threshold)
				require.Equal(t, 2, target.Min)
			},
		},
		{
			name:      "zero parts",
			secret:    []byte("test"),
			parts:     0,
			threshold: 0,
			requireErr: func(t *testing.T, err error) {
				var target shamir.ThresholdTooSmallError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Threshold)
				require.Equal(t, 2, target.Min)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			shares, err := shamir.Split(tt.secret, tt.parts, tt.threshold)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, shares)
		})
	}
}

func TestCombineErrors(t *testing.T) {
	shares, err := shamir.Split([]byte("test"), 5, 4)
	require.NoError(t, err)

	withXCoordinate := func(share []byte, x byte) []byte {
		clone := append([]byte(nil), share...)
		clone[len(clone)-1] = x
		return clone
	}

	tests := []struct {
		name       string
		shares     [][]byte
		requireErr func(*testing.T, error)
	}{
		{
			name:   "no shares",
			shares: nil,
			requireErr: func(t *testing.T, err error) {
				var target shamir.SharesTooFewError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Count)
				require.Equal(t, 2, target.Min)
			},
		},
		{
			name:   "single share",
			shares: [][]byte{shares[0]},
			requireErr: func(t *testing.T, err error) {
				var target shamir.SharesTooFewError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Count)
				require.Equal(t, 2, target.Min)
			},
		},
		{
			name:   "inconsistent lengths",
			shares: [][]byte{[]byte("foo"), []byte("ba")},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareLengthMismatchError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
				require.Equal(t, 2, target.Length)
				require.Equal(t, 3, target.Want)
			},
		},
		{
			name:   "empty share",
			shares: [][]byte{{}, {}},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareTooShortError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Index)
				require.Equal(t, 0, target.Length)
				require.Equal(t, 1, target.Min)
			},
		},
		{
			name: "duplicate x-coordinates",
			shares: [][]byte{
				shares[0],
				withXCoordinate(shares[1], shares[0][len(shares[0])-1]),
			},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareXDuplicateError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
				require.Equal(t, 0, target.PrevIndex)
				require.Equal(t, shares[0][len(shares[0])-1], target.X)
			},
		},
		{
			name:   "zero x-coordinate",
			shares: [][]byte{withXCoordinate(shares[0], 0), shares[1]},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareXZeroError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Index)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret, err := shamir.Combine(tt.shares)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, secret)
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
	tests := []struct {
		name string
		x    uint8
		want uint8
	}{
		{name: "x=0", x: 0, want: 42},
		{name: "x=1", x: 1, want: 88},
		{name: "x=2", x: 2, want: 159},
		{name: "x=7", x: 7, want: 195},
		{name: "x=255", x: 255, want: 115},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shamir.PolyEvaluate(coefficients, tt.x))
		})
	}
}

func TestPolyWeights(t *testing.T) {
	xCoords := []uint8{1, 2, 7}
	tests := []struct {
		name string
		x    uint8
		want []uint8
	}{
		{name: "x=0", x: 0, want: []uint8{165, 99, 199}},
		{name: "x=1", x: 1, want: []uint8{1, 0, 0}},
		{name: "x=2", x: 2, want: []uint8{0, 1, 0}},
		{name: "x=7", x: 7, want: []uint8{0, 0, 1}},
		{name: "x=255", x: 255, want: []uint8{138, 147, 24}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shamir.PolyWeights(xCoords, tt.x))
		})
	}
}

func TestFieldAdd(t *testing.T) {
	tests := []struct {
		name string
		a, b uint8
		want uint8
	}{
		{name: "self cancels", a: 16, b: 16, want: 0},
		{name: "small xor", a: 3, b: 4, want: 7},
		{name: "zero is identity", a: 3, b: 0, want: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shamir.FieldAdd(tt.a, tt.b))
		})
	}
}

func TestFieldMul(t *testing.T) {
	tests := []struct {
		name string
		a, b uint8
		want uint8
	}{
		{name: "right zero", a: 3, b: 0, want: 0},
		{name: "left zero", a: 0, b: 3, want: 0},
		{name: "right one", a: 3, b: 1, want: 3},
		{name: "left one", a: 1, b: 3, want: 3},
		{name: "three times seven", a: 3, b: 7, want: 9},
		{name: "seven times three", a: 7, b: 3, want: 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shamir.FieldMul(tt.a, tt.b))
		})
	}
}

func TestFieldDiv(t *testing.T) {
	tests := []struct {
		name string
		a, b uint8
		want uint8
	}{
		{name: "zero numerator", a: 0, b: 3, want: 0},
		{name: "self divides to one", a: 3, b: 3, want: 1},
		{name: "nine over three", a: 9, b: 3, want: 7},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shamir.FieldDiv(tt.a, tt.b))
		})
	}
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
