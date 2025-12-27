package hashx

import (
	"crypto/sha256"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/ripemd160"
	"golang.org/x/crypto/sha3"
)

func Sha256Sum(data []byte) []byte {
	hasher := sha256.New()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

func Keccak256Sum(data []byte) []byte {
	hasher := sha3.NewLegacyKeccak256()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

func RipeMD160Sum(data []byte) []byte {
	hasher := ripemd160.New()
	_, _ = hasher.Write(data)
	return hasher.Sum(nil)
}

func Blake2b256Sum(data []byte) []byte {
	digest := blake2b.Sum256(data)
	return digest[:]
}
