package hashx_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/hashx"
)

func TestSha256Sum(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		hexDigest string
	}{
		{
			name:      "nil",
			data:      nil,
			hexDigest: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:      "abc",
			data:      []byte("abc"),
			hexDigest: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := hashx.Sha256Sum(tt.data)
			hexDigest := hex.EncodeToString(digest)
			require.Equal(t, tt.hexDigest, hexDigest)
		})
	}
}

func TestTaggedSha256Sum(t *testing.T) {
	tests := []struct {
		name      string
		tag       string
		data      []byte
		hexDigest string
	}{
		{
			name:      "empty data",
			tag:       "TapTweak",
			data:      nil,
			hexDigest: "8aa4229474ab0100b2d6f0687f031d1fc9d8eef92a042ad97d279bff456b15e4",
		},
		{
			name:      "abc",
			tag:       "Tag",
			data:      []byte("abc"),
			hexDigest: "244b09c843d472a1ac5c8be3ddfcb99409ca6145fdb3f0764ea4e9d8f1c29e9f",
		},
		{
			name:      "tap tweak vector",
			tag:       "TapTweak",
			data:      mustDecodeHex(t, "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"),
			hexDigest: "2ca01ed85cf6b6526f73d39a1111cd80333bfdc00ce98992859848a90a6f0258",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := hashx.TaggedSha256Sum(tt.tag, tt.data)
			hexDigest := hex.EncodeToString(digest)
			require.Equal(t, tt.hexDigest, hexDigest)
		})
	}
}

func TestKeccak256Sum(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		hexDigest string
	}{
		{
			name:      "nil",
			data:      nil,
			hexDigest: "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
		},
		{
			name:      "abc",
			data:      []byte("abc"),
			hexDigest: "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := hashx.Keccak256Sum(tt.data)
			hexDigest := hex.EncodeToString(digest)
			require.Equal(t, tt.hexDigest, hexDigest)
		})
	}
}

func TestRipeMD160Sum(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		hexDigest string
	}{
		{
			name:      "nil",
			data:      nil,
			hexDigest: "9c1185a5c5e9fc54612808977ee8f548b2258d31",
		},
		{
			name:      "abc",
			data:      []byte("abc"),
			hexDigest: "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := hashx.RipeMD160Sum(tt.data)
			hexDigest := hex.EncodeToString(digest)
			require.Equal(t, tt.hexDigest, hexDigest)
		})
	}
}

func TestBlake2b256Sum(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		hexDigest string
	}{
		{
			name:      "nil",
			data:      nil,
			hexDigest: "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
		},
		{
			name:      "abc",
			data:      []byte("abc"),
			hexDigest: "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			digest := hashx.Blake2b256Sum(tt.data)
			hexDigest := hex.EncodeToString(digest)
			require.Equal(t, tt.hexDigest, hexDigest)
		})
	}
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	require.NoError(t, err)
	return data
}
