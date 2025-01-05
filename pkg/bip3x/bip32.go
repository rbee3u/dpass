package bip3x

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/rbee3u/dpass/third_party/github.com/decred/dcrd/dcrec/secp256k1"
)

const (
	FirstHardenedChild = uint32(0x80000000)
)

type InvalidPathError struct{ v []uint32 }

func (e InvalidPathError) Error() string {
	return fmt.Sprintf("bip32: invalid path(%v)", e.v)
}

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

func secp256k1AssertSk(sk []byte) {
	if zero := [32]byte{}; bytes.Equal(sk, zero[:]) {
		panic("bip32: secp256k1: sk is too small")
	}
	if bytes.Compare(sk, secp256k1.S256().N.Bytes()) >= 0 {
		panic("bip32: secp256k1: sk is too large")
	}
}

func Ed25519DeriveSk(seed []byte, path []uint32) ([]byte, error) {
	sk, cc := calculateHmacSha512([]byte("ed25519 seed"), seed)
	for i := range path {
		if path[i] < FirstHardenedChild {
			return nil, InvalidPathError{v: path}
		}
		data := make([]byte, 37)
		copy(data[1:33], sk)
		binary.BigEndian.PutUint32(data[33:], path[i])
		sk, cc = calculateHmacSha512(cc, data)
	}
	return sk, nil
}

func calculateHmacSha512(key, data []byte) ([]byte, []byte) {
	hasher := hmac.New(sha512.New, key)
	_, _ = hasher.Write(data)
	digest := hasher.Sum(nil)
	return digest[:32], digest[32:]
}
