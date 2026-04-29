package bip3x

import (
	"crypto/rand"
	"crypto/sha512"
	_ "embed"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/pbkdf2"

	"github.com/rbee3u/dpass/pkg/hashx"
)

// BIP-39 bit-width limits and conversion ratios.
const (
	// BitsPerByte is the number of bits in one byte of entropy or output.
	BitsPerByte = 8
	// BitsPerWord is the bit width of one BIP-39 word index in the embedded list.
	BitsPerWord = 11

	// EntropyBitsStep is the entropy size granularity in bits (one word needs 11 bits; checksum scales with entropy).
	EntropyBitsStep = 32
	// EntropyBitsMin is the smallest entropy size accepted by BIP-39.
	EntropyBitsMin = 4 * EntropyBitsStep
	// EntropyBitsMax is the largest entropy size accepted by BIP-39.
	EntropyBitsMax = 8 * EntropyBitsStep

	// SentenceBitsStep is mnemonic length granularity: 11 bits per word plus checksum bits per 32 bits of entropy.
	SentenceBitsStep = 33
	// SentenceBitsMin is the bit length of the shortest supported mnemonic sentence.
	SentenceBitsMin = 4 * SentenceBitsStep
	// SentenceBitsMax is the bit length of the longest supported mnemonic sentence.
	SentenceBitsMax = 8 * SentenceBitsStep
)

// InvalidEntropyBitsError reports entropy length (in bits) outside BIP-39 allowed sizes.
type InvalidEntropyBitsError struct {
	// Bits is the rejected entropy length in bits.
	Bits int
}

func (e InvalidEntropyBitsError) Error() string {
	return fmt.Sprintf("bip39: invalid entropy bits (got %d, must be multiple of %d within [%d, %d])",
		e.Bits, EntropyBitsStep, EntropyBitsMin, EntropyBitsMax)
}

// InvalidSentenceBitsError reports mnemonic word-count bits that do not match a valid checksum layout.
type InvalidSentenceBitsError struct {
	// Bits is the rejected mnemonic length expressed in bits.
	Bits int
}

func (e InvalidSentenceBitsError) Error() string {
	return fmt.Sprintf("bip39: invalid sentence bits (got %d, must be multiple of %d within [%d, %d])",
		e.Bits, SentenceBitsStep, SentenceBitsMin, SentenceBitsMax)
}

// WordNotFoundError reports a mnemonic word missing from the embedded English wordlist.
type WordNotFoundError struct {
	// Word is the mnemonic token missing from the embedded English wordlist.
	Word string
}

func (e WordNotFoundError) Error() string {
	return fmt.Sprintf("bip39: word %q not found in English wordlist", e.Word)
}

// DigestMismatchError reports a failed BIP-39 checksum when decoding a mnemonic to entropy.
type DigestMismatchError struct {
	// Got is the checksum value encoded in the mnemonic.
	Got uint32
	// Want is the checksum recomputed from the decoded entropy.
	Want uint32
}

func (e DigestMismatchError) Error() string {
	return fmt.Sprintf("bip39: invalid mnemonic checksum (got %d, want %d)", e.Got, e.Want)
}

// Embedded wordlist caches used by mnemonic encoding and decoding.
var (
	//go:embed english.txt
	// english holds the raw embedded BIP-39 English wordlist text.
	english string
	// value2word maps 11-bit indices to English words (order matches BIP-39).
	value2word = strings.Fields(english)
	// word2value is the inverse of value2word for mnemonic parsing.
	word2value = generateWord2Value()
)

// generateWord2Value builds a reverse map from English word to 11-bit index.
func generateWord2Value() map[string]uint32 {
	word2value := make(map[string]uint32)
	for value, word := range value2word {
		word2value[word] = uint32(value)
	}

	return word2value
}

// CreateEntropyRandomly returns cryptographically random entropy; entropySize is the length in bits.
func CreateEntropyRandomly(entropySize int) ([]byte, error) {
	if entropySize%EntropyBitsStep != 0 || entropySize < EntropyBitsMin || entropySize > EntropyBitsMax {
		return nil, InvalidEntropyBitsError{Bits: entropySize}
	}
	entropy := make([]byte, entropySize/BitsPerByte)
	if _, err := io.ReadFull(rand.Reader, entropy); err != nil {
		return nil, err
	}
	return entropy, nil
}

// EntropyToMnemonic encodes entropy bytes as a space-separated BIP-39 English mnemonic.
func EntropyToMnemonic(entropy []byte) (string, error) {
	entropyBits := len(entropy) * BitsPerByte
	if entropyBits%EntropyBitsStep != 0 || entropyBits < EntropyBitsMin || entropyBits > EntropyBitsMax {
		return "", InvalidEntropyBitsError{Bits: entropyBits}
	}
	digestBits := entropyBits / EntropyBitsStep
	sentence := make([]string, 0, digestBits*SentenceBitsStep/BitsPerWord)
	remain, shift := uint32(0), 0
	for i := range entropy {
		remain, shift = (remain<<BitsPerByte)|uint32(entropy[i]), shift+BitsPerByte
		for shift >= BitsPerWord {
			reducedShift := shift - BitsPerWord
			sentence = append(sentence, value2word[remain>>reducedShift])
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}
	digest := uint32(hashx.Sha256Sum(entropy)[0] >> (BitsPerByte - digestBits))
	sentence = append(sentence, value2word[(remain<<digestBits)|digest])
	return strings.Join(sentence, " "), nil
}

// MnemonicToSeed validates mnemonic length, wordlist membership, and checksum,
// then returns the 64-byte PBKDF2-HMAC-SHA512 seed using
// "mnemonic"+password as salt and 2048 iterations.
func MnemonicToSeed(mnemonic string, password string) ([]byte, error) {
	sentence := strings.Fields(mnemonic)
	sentenceBits := len(sentence) * BitsPerWord
	if sentenceBits%SentenceBitsStep != 0 || sentenceBits < SentenceBitsMin || sentenceBits > SentenceBitsMax {
		return nil, InvalidSentenceBitsError{Bits: sentenceBits}
	}
	digestBits := sentenceBits / SentenceBitsStep
	entropy := make([]byte, 0, digestBits*EntropyBitsStep/BitsPerByte)
	remain, shift := uint32(0), 0
	for _, word := range sentence {
		value, exist := word2value[word]
		if !exist {
			return nil, WordNotFoundError{Word: word}
		}
		remain, shift = (remain<<BitsPerWord)|value, shift+BitsPerWord
		for shift > BitsPerByte {
			reducedShift := shift - BitsPerByte
			entropy = append(entropy, byte(remain>>reducedShift))
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}
	if digest := uint32(hashx.Sha256Sum(entropy)[0] >> (BitsPerByte - digestBits)); remain != digest {
		return nil, DigestMismatchError{Got: remain, Want: digest}
	}
	salt := append([]byte("mnemonic"), password...)
	return pbkdf2.Key([]byte(strings.Join(sentence, " ")), salt, 2048, 64, sha512.New), nil
}
