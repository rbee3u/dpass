package bip3x

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/rbee3u/dpass/pkg/secp256k1"
)

// BIP-32 shared constants.
const (
	// FirstHardenedChild is the BIP-32 hardened index offset (2^31).
	FirstHardenedChild = uint32(0x80000000)
)

// InvalidPathError reports a derivation path incompatible with the selected curve rules.
type InvalidPathError struct {
	Path []uint32
}

func (e InvalidPathError) Error() string {
	return fmt.Sprintf("bip32: invalid derivation path %v (every index must be hardened)", e.Path)
}

// Secp256k1DeriveSk derives a 32-byte secp256k1 secret key from BIP-39 seed bytes and a BIP-32 path.
// Non-hardened steps use compressed pubkey data; hardened steps use the parent secret.
func Secp256k1DeriveSk(seed []byte, path []uint32) ([]byte, error) {
	sk, cc := calculateHmacSha512([]byte("Bitcoin seed"), seed)
	secp256k1AssertSk(sk)

	for i := range path {
		data := make([]byte, 37)

		if path[i] < FirstHardenedChild {
			x, y := secp256k1.S256().ScalarBaseMult(sk)
			data[0] = 2
			x.FillBytes(data[1:33])
			data[0] += byte(y.Bit(0))
		} else {
			copy(data[1:33], sk)
		}

		binary.BigEndian.PutUint32(data[33:], path[i])

		sum := new(big.Int).SetBytes(sk)
		sk, cc = calculateHmacSha512(cc, data)
		secp256k1AssertSk(sk)
		sum.Add(sum, new(big.Int).SetBytes(sk))
		sum.Mod(sum, secp256k1.S256().N)
		sum.FillBytes(sk)
	}

	return sk, nil
}

// secp256k1AssertSk panics if sk is zero or not less than curve order N (invalid BIP-32 secret).
func secp256k1AssertSk(sk []byte) {
	if zero := [32]byte{}; bytes.Equal(sk, zero[:]) {
		panic("bip32: secp256k1: sk is too small")
	}

	if bytes.Compare(sk, secp256k1.S256().N.Bytes()) >= 0 {
		panic("bip32: secp256k1: sk is too large")
	}
}

// Ed25519DeriveSk derives a 32-byte Ed25519 seed per SLIP-0010; every path index must be hardened.
func Ed25519DeriveSk(seed []byte, path []uint32) ([]byte, error) {
	sk, cc := calculateHmacSha512([]byte("ed25519 seed"), seed)

	for i := range path {
		if path[i] < FirstHardenedChild {
			return nil, InvalidPathError{Path: path}
		}

		data := make([]byte, 37)
		copy(data[1:33], sk)
		binary.BigEndian.PutUint32(data[33:], path[i])
		sk, cc = calculateHmacSha512(cc, data)
	}

	return sk, nil
}

// calculateHmacSha512 returns the left 32 bytes (secret/chain material) and right 32 bytes (chain code).
func calculateHmacSha512(key, data []byte) ([]byte, []byte) {
	hasher := hmac.New(sha512.New, key)
	_, _ = hasher.Write(data)
	digest := hasher.Sum(nil)

	return digest[:32], digest[32:]
}
