// Package hashx wraps hash functions used by the supported chains.
package hashx

import (
	"crypto/sha256"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

// Sha256Sum returns the 32-byte SHA-256 digest of data.
func Sha256Sum(data []byte) []byte {
	hasher := sha256.New()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

// Keccak256Sum returns the 32-byte Keccak-256 digest (Ethereum pre-SHA3 variant).
func Keccak256Sum(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

// RipeMD160Sum returns the 20-byte RIPEMD-160 digest of data.
func RipeMD160Sum(data []byte) []byte {
	hasher := ripemd160.New()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

// Blake2b256Sum returns the 32-byte BLAKE2b-256 digest of data.
func Blake2b256Sum(data []byte) []byte {
	digest := blake2b.Sum256(data)
	return digest[:]
}
