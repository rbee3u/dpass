package hashx_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/rbee3u/dpass/pkg/hashx"
)

func TestHashSums(t *testing.T) {
	tests := []struct {
		name    string
		sum     func([]byte) []byte
		input   []byte
		wantHex string
		wantLen int
	}{
		{
			name:    "sha256 nil input",
			sum:     hashx.Sha256Sum,
			input:   nil,
			wantHex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantLen: 32,
		},
		{
			name:    "sha256 abc",
			sum:     hashx.Sha256Sum,
			input:   []byte("abc"),
			wantHex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
			wantLen: 32,
		},
		{
			name:    "keccak256 nil input",
			sum:     hashx.Keccak256Sum,
			input:   nil,
			wantHex: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
			wantLen: 32,
		},
		{
			name:    "keccak256 abc",
			sum:     hashx.Keccak256Sum,
			input:   []byte("abc"),
			wantHex: "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
			wantLen: 32,
		},
		{
			name:    "ripemd160 nil input",
			sum:     hashx.RipeMD160Sum,
			input:   nil,
			wantHex: "9c1185a5c5e9fc54612808977ee8f548b2258d31",
			wantLen: 20,
		},
		{
			name:    "ripemd160 abc",
			sum:     hashx.RipeMD160Sum,
			input:   []byte("abc"),
			wantHex: "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
			wantLen: 20,
		},
		{
			name:    "blake2b256 nil input",
			sum:     hashx.Blake2b256Sum,
			input:   nil,
			wantHex: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
			wantLen: 32,
		},
		{
			name:    "blake2b256 abc",
			sum:     hashx.Blake2b256Sum,
			input:   []byte("abc"),
			wantHex: "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
			wantLen: 32,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := append([]byte(nil), tt.input...)

			got := tt.sum(input)

			require.Len(t, got, tt.wantLen)
			require.Equal(t, tt.wantHex, hex.EncodeToString(got))
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
