// Package bip32 implements BIP-32 and SLIP-0010 child-key derivation helpers.
package bip32

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/rbee3u/dpass/pkg/secp256k1"
)

const (
	// FirstHardenedChild is the BIP-32 hardened index offset (2^31).
	FirstHardenedChild = uint32(0x80000000)
)

// InvalidPathError reports a derivation path incompatible with the selected curve rules.
type InvalidPathError struct {
	// Path is the full derivation path rejected by the curve-specific rules.
	Path []uint32
}

func (e InvalidPathError) Error() string {
	return fmt.Sprintf("bip32: invalid derivation path %v (every index must be hardened)", e.Path)
}

// InvalidSecp256k1MasterKeyError reports invalid secp256k1 master key material.
type InvalidSecp256k1MasterKeyError struct{}

func (e InvalidSecp256k1MasterKeyError) Error() string {
	return "bip32: invalid secp256k1 master key material"
}

// InvalidSecp256k1IntermediateKeyError reports invalid secp256k1 child
// intermediate key material.
type InvalidSecp256k1IntermediateKeyError struct {
	// Depth is the zero-based derivation step that produced the invalid material.
	Depth int
	// Index is the child index used at Depth.
	Index uint32
}

func (e InvalidSecp256k1IntermediateKeyError) Error() string {
	return fmt.Sprintf("bip32: invalid secp256k1 child key material at depth %d index %d", e.Depth, e.Index)
}

// InvalidSecp256k1ChildKeyError reports a derived secp256k1 child key reduced to zero.
type InvalidSecp256k1ChildKeyError struct {
	// Depth is the zero-based derivation step that produced the zero key.
	Depth int
	// Index is the child index used at Depth.
	Index uint32
}

func (e InvalidSecp256k1ChildKeyError) Error() string {
	return fmt.Sprintf("bip32: invalid secp256k1 child key at depth %d index %d", e.Depth, e.Index)
}

// Secp256k1DeriveSk derives a 32-byte secp256k1 secret key from BIP-39 seed
// bytes and a BIP-32 path. Non-hardened steps use compressed pubkey data;
// hardened steps use the parent secret.
func Secp256k1DeriveSk(seed []byte, path []uint32) ([]byte, error) {
	sk, cc := hmacSha512([]byte("Bitcoin seed"), seed)
	if !isValidSecp256k1Secret(sk) {
		return nil, InvalidSecp256k1MasterKeyError{}
	}
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
		childSk, childCC := hmacSha512(cc, data)
		if !isValidSecp256k1Secret(childSk) {
			return nil, InvalidSecp256k1IntermediateKeyError{Depth: i, Index: path[i]}
		}
		sum.Add(sum, new(big.Int).SetBytes(childSk))
		sum.Mod(sum, secp256k1.S256().N)
		if sum.Sign() == 0 {
			return nil, InvalidSecp256k1ChildKeyError{Depth: i, Index: path[i]}
		}
		sum.FillBytes(childSk)
		sk, cc = childSk, childCC
	}
	return sk, nil
}

// isValidSecp256k1Secret reports whether sk is within secp256k1 private-key bounds.
func isValidSecp256k1Secret(sk []byte) bool {
	if zero := [32]byte{}; bytes.Equal(sk, zero[:]) {
		return false
	}
	if bytes.Compare(sk, secp256k1.S256().N.Bytes()) >= 0 {
		return false
	}
	return true
}

// Ed25519DeriveSk derives a 32-byte Ed25519 seed per SLIP-0010; every path
// index must be hardened.
func Ed25519DeriveSk(seed []byte, path []uint32) ([]byte, error) {
	sk, cc := hmacSha512([]byte("ed25519 seed"), seed)
	for i := range path {
		if path[i] < FirstHardenedChild {
			return nil, InvalidPathError{Path: path}
		}
		data := make([]byte, 37)
		copy(data[1:33], sk)
		binary.BigEndian.PutUint32(data[33:], path[i])
		sk, cc = hmacSha512(cc, data)
	}
	return sk, nil
}

// hmacSha512 returns the left 32 bytes (secret/chain material) and right 32
// bytes (chain code).
var hmacSha512 = func(key, data []byte) ([]byte, []byte) {
	hasher := hmac.New(sha512.New, key)
	_, _ = hasher.Write(data)
	digest := hasher.Sum(nil)
	return digest[:32], digest[32:]
}
