package basebb_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/basebb"
)

func TestTransform(t *testing.T) {
	tests := []struct {
		name  string
		iBase uint32
		oBase uint32
		in    []byte
		out   []byte
	}{
		{
			name:  "binary to decimal 1010",
			iBase: 2,
			oBase: 10,
			in:    []byte{1, 0, 1, 0},
			out:   []byte{1, 0},
		},
		{
			name:  "decimal to binary 10",
			iBase: 10,
			oBase: 2,
			in:    []byte{1, 0},
			out:   []byte{1, 0, 1, 0},
		},
		{
			name:  "leading zeros preserved",
			iBase: 256,
			oBase: 58,
			in:    []byte{0, 0, 1},
			out:   []byte{0, 0, 1},
		},
		{
			name:  "empty input",
			iBase: 10,
			oBase: 2,
			in:    []byte{},
			out:   []byte{},
		},
		{
			name:  "single zero",
			iBase: 256,
			oBase: 58,
			in:    []byte{0},
			out:   []byte{0},
		},
		{
			name:  "round-trip base10 to base16",
			iBase: 10,
			oBase: 16,
			in:    []byte{2, 5, 5},
			out:   []byte{15, 15},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := basebb.Transform(tt.iBase, tt.oBase, tt.in)
			require.NoError(t, err)
			require.Equal(t, tt.out, out)
		})
	}
}

func TestTransformRoundTrip(t *testing.T) {
	in := []byte{0, 0, 0x48, 0x65, 0x6c, 0x6c, 0x6f}
	mid, err := basebb.Transform(256, 58, in)
	require.NoError(t, err)
	got, err := basebb.Transform(58, 256, mid)
	require.NoError(t, err)
	require.Equal(t, in, got)
}

func TestTransformErrors(t *testing.T) {
	tests := []struct {
		name       string
		iBase      uint32
		oBase      uint32
		in         []byte
		requireErr func(*testing.T, error)
	}{
		{
			name:  "iBase too small",
			iBase: 1,
			oBase: 10,
			in:    []byte{0},
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidBaseError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(1), target.Base)
			},
		},
		{
			name:  "iBase too large",
			iBase: 257,
			oBase: 10,
			in:    []byte{0},
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidBaseError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(257), target.Base)
			},
		},
		{
			name:  "oBase too small",
			iBase: 10,
			oBase: 0,
			in:    []byte{0},
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidBaseError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(0), target.Base)
			},
		},
		{
			name:  "oBase too large",
			iBase: 10,
			oBase: 300,
			in:    []byte{0},
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidBaseError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(300), target.Base)
			},
		},
		{
			name:  "digit exceeds iBase",
			iBase: 10,
			oBase: 2,
			in:    []byte{1, 10},
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte(10), target.Char)
			},
		},
		{
			name:  "digit far exceeds iBase",
			iBase: 2,
			oBase: 10,
			in:    []byte{0, 5},
			requireErr: func(t *testing.T, err error) {
				var target basebb.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte(5), target.Char)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := basebb.Transform(tt.iBase, tt.oBase, tt.in)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, out)
		})
	}
}
