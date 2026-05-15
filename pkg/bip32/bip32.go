// Package bip32 implements BIP-32 and SLIP-0010 child-key derivation helpers.
package bip32

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"math/big"

	"github.com/rbee3u/dpass/pkg/secp256k1"
)

// FirstHardenedChild is the BIP-32 hardened index offset (2^31).
const FirstHardenedChild uint32 = 0x80000000

// Secp256k1DeriveSk derives a 32-byte secp256k1 secret key from BIP-39 seed
// bytes and a BIP-32 path. Non-hardened steps use compressed pubkey data;
// hardened steps use the parent secret.
func Secp256k1DeriveSk(seed []byte, path []uint32) ([]byte, error) {
	sk, cc := hmacSha512([]byte("Bitcoin seed"), seed)
	skBig := new(big.Int).SetBytes(sk)
	if skBig.Sign() == 0 || skBig.Cmp(secp256k1.S256().N) >= 0 {
		return nil, ErrInvalidSecp256k1MasterKey
	}
	for i := range path {
		data := make([]byte, 37)
		if path[i] < FirstHardenedChild {
			x, y := secp256k1.S256().ScalarBaseMult(sk)
			data[0] = 2 + byte(y.Bit(0))
			x.FillBytes(data[1:33])
		} else {
			copy(data[1:33], sk)
		}
		binary.BigEndian.PutUint32(data[33:], path[i])
		ik, ic := hmacSha512(cc, data)
		ikBig := new(big.Int).SetBytes(ik)
		if ikBig.Cmp(secp256k1.S256().N) >= 0 {
			return nil, InvalidSecp256k1InterKeyError{Depth: i, Index: path[i]}
		}
		skBig.Add(skBig, ikBig)
		skBig.Mod(skBig, secp256k1.S256().N)
		if skBig.Sign() == 0 {
			return nil, InvalidSecp256k1ChildKeyError{Depth: i, Index: path[i]}
		}
		skBig.FillBytes(sk)
		cc = ic
	}
	return sk, nil
}

// Ed25519DeriveSk derives a 32-byte ed25519 secret key from BIP-39 seed bytes
// and a BIP-32 path. All path indices must be hardened.
func Ed25519DeriveSk(seed []byte, path []uint32) ([]byte, error) {
	sk, cc := hmacSha512([]byte("ed25519 seed"), seed)
	for i := range path {
		if path[i] < FirstHardenedChild {
			return nil, InvalidEd25519PathError{Path: path}
		}
		data := make([]byte, 37)
		copy(data[1:33], sk)
		binary.BigEndian.PutUint32(data[33:], path[i])
		sk, cc = hmacSha512(cc, data)
	}
	return sk, nil
}

var hmacSha512 = func(key, data []byte) ([]byte, []byte) {
	hasher := hmac.New(sha512.New, key)
	_, _ = hasher.Write(data)
	digest := hasher.Sum(nil)
	return digest[:32], digest[32:]
}
