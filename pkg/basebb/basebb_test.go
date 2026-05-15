package basebb_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/basebb"
	"github.com/rbee3u/dpass/pkg/testx"
)

func TestTransform(t *testing.T) {
	tests := []struct {
		name    string
		inBase  uint32
		outBase uint32
		in      []uint32
		out     []uint32
	}{
		{
			name:    "decimal to binary",
			inBase:  10,
			outBase: 2,
			in:      []uint32{1, 0},
			out:     []uint32{1, 0, 1, 0},
		},
		{
			name:    "binary to decimal",
			inBase:  2,
			outBase: 10,
			in:      []uint32{1, 0, 1, 0},
			out:     []uint32{1, 0},
		},
		{
			name:    "decimal to hexadecimal",
			inBase:  10,
			outBase: 16,
			in:      []uint32{2, 5, 5},
			out:     []uint32{15, 15},
		},
		{
			name:    "hexadecimal to decimal",
			inBase:  16,
			outBase: 10,
			in:      []uint32{15, 15},
			out:     []uint32{2, 5, 5},
		},
		{
			name:    "leading zeros preserved",
			inBase:  256,
			outBase: 58,
			in:      []uint32{0, 0, 1},
			out:     []uint32{0, 0, 1},
		},
		{
			name:    "all zeros preserved",
			inBase:  256,
			outBase: 58,
			in:      []uint32{0, 0, 0, 0},
			out:     []uint32{0, 0, 0, 0},
		},
		{
			name:    "empty input",
			inBase:  10,
			outBase: 2,
			in:      []uint32{},
			out:     []uint32{},
		},
		{
			name:    "wide digit to decimal",
			inBase:  1000,
			outBase: 10,
			in:      []uint32{999},
			out:     []uint32{9, 9, 9},
		},
		{
			name:    "max base to decimal",
			inBase:  math.MaxUint32,
			outBase: 10,
			in:      []uint32{1, 0},
			out:     []uint32{4, 2, 9, 4, 9, 6, 7, 2, 9, 5},
		},
		{
			name:    "max base identity",
			inBase:  math.MaxUint32,
			outBase: math.MaxUint32,
			in:      []uint32{math.MaxUint32 - 1, math.MaxUint32 - 1},
			out:     []uint32{math.MaxUint32 - 1, math.MaxUint32 - 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := basebb.Transform(tt.inBase, tt.outBase, tt.in)
			require.NoError(t, err)
			testx.EqualSlice(t, tt.out, out)
		})
	}
}

func TestTransformErrors(t *testing.T) {
	tests := []struct {
		name       string
		inBase     uint32
		outBase    uint32
		in         []uint32
		requireErr func(*testing.T, error)
	}{
		{
			name:    "invalid in base",
			inBase:  1,
			outBase: 10,
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidInBaseError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(1), target.InBase)
			},
		},
		{
			name:    "invalid out base",
			inBase:  10,
			outBase: 1,
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidOutBaseError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(1), target.OutBase)
			},
		},
		{
			name:    "invalid digit",
			inBase:  10,
			outBase: 2,
			in:      []uint32{0, 0, 10},
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidDigitError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 2, target.Offset)
				require.Equal(t, uint32(10), target.Digit)
				require.Equal(t, uint32(10), target.InBase)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := basebb.Transform(tt.inBase, tt.outBase, tt.in)
			require.Nil(t, out)
			tt.requireErr(t, err)
		})
	}
}
