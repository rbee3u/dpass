package bech32_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bech32"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		name string
		hrp  string
		vs0x string
		in0x string
		out  string
	}{
		{
			name: "bc1 witness v0 p2wpkh",
			hrp:  "bc",
			vs0x: "00",
			in0x: "751e76e8199196d454941c45d1b3a323f1433bd6",
			out:  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
		{
			name: "tb1 witness v0 p2wsh",
			hrp:  "tb",
			vs0x: "00",
			in0x: "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
			out:  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
		},
		{
			name: "bc1 witness v1 long program",
			hrp:  "bc",
			vs0x: "01",
			in0x: "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
			out:  "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
		},
		{
			name: "bc1 witness v16 short program",
			hrp:  "bc",
			vs0x: "10",
			in0x: "751e",
			out:  "bc1sw50qa3jx3s",
		},
		{
			name: "bc1 witness v2 16-byte program",
			hrp:  "bc",
			vs0x: "02",
			in0x: "751e76e8199196d454941c45d1b3a323",
			out:  "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
		},
		{
			name: "tb1 witness v0 leading zeros",
			hrp:  "tb",
			vs0x: "00",
			in0x: "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
			out:  "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs, err := hex.DecodeString(tt.vs0x)
			require.NoError(t, err)
			in, err := hex.DecodeString(tt.in0x)
			require.NoError(t, err)
			out, err := bech32.EncodeChecked(tt.hrp, vs, in)
			require.NoError(t, err)
			require.Equal(t, tt.out, out)
		})
	}
}

func TestEncodeErrors(t *testing.T) {
	tests := []struct {
		name       string
		hrp        string
		vs         []byte
		in         []byte
		requireErr func(*testing.T, error)
	}{
		{
			name: "empty hrp",
			requireErr: func(t *testing.T, err error) {
				var target bech32.EmptyHrpError
				require.ErrorAs(t, err, &target)
			},
		},
		{
			name: "uppercase hrp",
			hrp:  "BC",
			requireErr: func(t *testing.T, err error) {
				var target bech32.InvalidHrpCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte('B'), target.Char)
			},
		},
		{
			name: "invalid version value",
			hrp:  "bc",
			vs:   []byte{32},
			requireErr: func(t *testing.T, err error) {
				var target bech32.InvalidDataValueError
				require.ErrorAs(t, err, &target)
				require.Equal(t, "version", target.Part)
				require.Equal(t, 0, target.Offset)
				require.Equal(t, byte(32), target.Value)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := bech32.EncodeChecked(tt.hrp, tt.vs, tt.in)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Empty(t, out)
		})
	}
}
