package hashx_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/rbee3u/dpass/pkg/hashx"
)

func TestSha256Sum(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		hex0x  string
		length int
	}{
		{
			name:   "nil input",
			input:  nil,
			hex0x:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			length: 32,
		},
		{
			name:   "abc",
			input:  []byte("abc"),
			hex0x:  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			length: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]byte(nil), tt.input...)

			got := hashx.Sha256Sum(input)

			require.Len(t, got, tt.length)
			require.Equal(t, tt.hex0x, hex.EncodeToString(got))
			require.Equal(t, tt.input, input)
		})
	}
}

func TestKeccak256Sum(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		hex0x  string
		length int
	}{
		{
			name:   "nil input",
			input:  nil,
			hex0x:  "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
			length: 32,
		},
		{
			name:   "abc",
			input:  []byte("abc"),
			hex0x:  "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
			length: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]byte(nil), tt.input...)

			got := hashx.Keccak256Sum(input)

			require.Len(t, got, tt.length)
			require.Equal(t, tt.hex0x, hex.EncodeToString(got))
			require.Equal(t, tt.input, input)
		})
	}
}

func TestRipeMD160Sum(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		hex0x  string
		length int
	}{
		{
			name:   "nil input",
			input:  nil,
			hex0x:  "9c1185a5c5e9fc54612808977ee8f548b2258d31",
			length: 20,
		},
		{
			name:   "abc",
			input:  []byte("abc"),
			hex0x:  "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
			length: 20,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]byte(nil), tt.input...)

			got := hashx.RipeMD160Sum(input)

			require.Len(t, got, tt.length)
			require.Equal(t, tt.hex0x, hex.EncodeToString(got))
			require.Equal(t, tt.input, input)
		})
	}
}

func TestBlake2b256Sum(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		hex0x  string
		length int
	}{
		{
			name:   "nil input",
			input:  nil,
			hex0x:  "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
			length: 32,
		},
		{
			name:   "abc",
			input:  []byte("abc"),
			hex0x:  "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
			length: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]byte(nil), tt.input...)

			got := hashx.Blake2b256Sum(input)

			require.Len(t, got, tt.length)
			require.Equal(t, tt.hex0x, hex.EncodeToString(got))
			require.Equal(t, tt.input, input)
		})
	}
}

func TestKeccak256SumUsesLegacyVariant(t *testing.T) {
	input := []byte("abc")

	legacy := hashx.Keccak256Sum(input)
	standard := sha3.Sum256(input)

	require.NotEqual(t, standard[:], legacy)
}
