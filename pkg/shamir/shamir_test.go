package shamir_test

import (
	"bytes"
	"iter"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/shamir"
)

func TestSplitCombine(t *testing.T) {
	tests := []struct {
		name      string
		secret    []byte
		parts     int
		threshold int
	}{
		{
			name:      "ascii secret",
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
			secret:    bytes.Repeat([]byte("t"), 256),
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
			name:      "threshold too small",
			secret:    []byte("test"),
			parts:     9,
			threshold: 1,
			requireErr: func(t *testing.T, err error) {
				var target shamir.SplitConstraintError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 9, target.Parts)
				require.Equal(t, 1, target.Threshold)
			},
		},
		{
			name:      "threshold greater than parts",
			secret:    []byte("test"),
			parts:     2,
			threshold: 3,
			requireErr: func(t *testing.T, err error) {
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
				var target shamir.SplitConstraintError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 256, target.Parts)
				require.Equal(t, 3, target.Threshold)
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
			},
		},
		{
			name:   "single share",
			shares: [][]byte{{42}},
			requireErr: func(t *testing.T, err error) {
				var target shamir.SharesTooFewError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Count)
			},
		},
		{
			name:   "empty share",
			shares: [][]byte{{42}, {}},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareTooShortError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
				require.Equal(t, 0, target.Length)
			},
		},
		{
			name:   "inconsistent lengths",
			shares: [][]byte{{42}, {0, 43}},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareLengthMismatchError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
				require.Equal(t, 2, target.Length)
				require.Equal(t, 1, target.Want)
			},
		},
		{
			name:   "zero x-coordinate",
			shares: [][]byte{{42}, {0}},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareXZeroError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
			},
		},
		{
			name:   "duplicate x-coordinate",
			shares: [][]byte{{42}, {42}},
			requireErr: func(t *testing.T, err error) {
				var target shamir.ShareXDuplicateError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Index)
				require.Equal(t, uint8(42), target.XCoordinate)
				require.Equal(t, 0, target.PrevIndex)
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
	xCoordinates := []uint8{1, 2, 7}
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
			require.Equal(t, tt.want, shamir.PolyWeights(xCoordinates, tt.x))
		})
	}
}

func TestFieldAdd(t *testing.T) {
	tests := []struct {
		name string
		x, y uint8
		want uint8
	}{
		{name: "self cancels", x: 16, y: 16, want: 0},
		{name: "small xor", x: 3, y: 4, want: 7},
		{name: "zero is identity", x: 3, y: 0, want: 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shamir.FieldAdd(tt.x, tt.y))
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
		x, y uint8
		want uint8
	}{
		{name: "divisor is one", x: 3, y: 1, want: 3},
		{name: "divide by self", x: 3, y: 3, want: 1},
		{name: "nine over three", x: 9, y: 3, want: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, shamir.FieldDiv(tt.x, tt.y))
		})
	}
}

func TestFieldInv(t *testing.T) {
	for x := uint8(1); x != 0; x++ {
		r := shamir.FieldMul(x, shamir.FieldInv(x))
		require.Equalf(t, uint8(1), r, "%d * %d^(-1) != 1", x, x)
	}
}

func combinations(s [][]byte, k int) iter.Seq[[][]byte] {
	return func(yield func([][]byte) bool) {
		if k < 0 || k > len(s) {
			return
		}
		indices := make([]int, k)
		for i := range indices {
			indices[i] = i
		}
		group := make([][]byte, k)
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
