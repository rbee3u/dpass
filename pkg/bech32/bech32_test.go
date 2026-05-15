package bech32_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bech32"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		name  string
		f     func(string, []byte, []byte) (string, error)
		hrp   string
		ver   []byte
		hexIn string
		out   string
	}{
		{
			name:  "bitcoin p2wpkh",
			f:     bech32.EncodeBech32,
			hrp:   "bc",
			ver:   []byte{0},
			hexIn: "0e52b8bfeecdd474149d029f77ed2d96670e86a5",
			out:   "bc1qpeft30lweh28g9yaq20h0mfdjensap49l98jft",
		},
		{
			name:  "sui private key",
			f:     bech32.EncodeBech32,
			hrp:   "suiprivkey",
			ver:   nil,
			hexIn: "004c979bf5a7b4751b6d756552738d69a9e34af151755e3d69ef5d090db7dbc6ff",
			out:   "suiprivkey1qpxf0xl457682xmdw4j4yuuddx57xjh32964u0tfaawsjrdhm0r07hdvan6",
		},
		{
			name:  "bitcoin taproot",
			f:     bech32.EncodeBech32m,
			hrp:   "bc",
			ver:   []byte{1},
			hexIn: "559448c450e028f1bc3b0daf92a437de4d1a6e8b3cb30a87a2796592f2c33b75",
			out:   "bc1p2k2y33zsuq50r0pmpkhe9fphmex35m5t8jes4paz09je9ukr8d6sntagnv",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, err := hex.DecodeString(tt.hexIn)
			require.NoError(t, err)
			out, err := tt.f(tt.hrp, tt.ver, in)
			require.NoError(t, err)
			require.Equal(t, tt.out, out)
		})
	}
}

func TestEncodeErrors(t *testing.T) {
	tests := []struct {
		name       string
		f          func(string, []byte, []byte) (string, error)
		hrp        string
		ver        []byte
		in         []byte
		requireErr func(*testing.T, error)
	}{
		{
			name: "hrp too short",
			f:    bech32.EncodeBech32,
			hrp:  "",
			requireErr: func(t *testing.T, err error) {
				var target bech32.InvalidHrpLengthError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Length)
			},
		},
		{
			name: "hrp too long",
			f:    bech32.EncodeBech32,
			hrp:  strings.Repeat("a", 84),
			requireErr: func(t *testing.T, err error) {
				var target bech32.InvalidHrpLengthError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 84, target.Length)
			},
		},
		{
			name: "invalid hrp character",
			f:    bech32.EncodeBech32,
			hrp:  "a b",
			requireErr: func(t *testing.T, err error) {
				var target bech32.InvalidHrpCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Offset)
				require.Equal(t, byte(' '), target.Char)
			},
		},
		{
			name: "invalid version value",
			f:    bech32.EncodeBech32,
			hrp:  "bc",
			ver:  []byte{31, 32},
			requireErr: func(t *testing.T, err error) {
				var target bech32.InvalidVerByteError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 1, target.Offset)
				require.Equal(t, byte(32), target.Byte)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.f(tt.hrp, tt.ver, tt.in)
			tt.requireErr(t, err)
			require.Empty(t, out)
		})
	}
}
