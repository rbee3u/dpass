// Package bip39 implements BIP-39 English mnemonic generation, validation, and
// seed derivation.
package bip39

import (
	"bytes"
	"crypto/sha512"
	_ "embed"
	"fmt"
	"io"
	"slices"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"

	"github.com/rbee3u/dpass/pkg/hashx"
)

const (
	// BitsPerByte is the bit width used when packing BIP-39 entropy and
	// checksums.
	BitsPerByte = 8
	// BitsPerWord is the bit width of one BIP-39 word index in the embedded list.
	BitsPerWord = 11
	// EntropySizeStep is the entropy size increment in bytes for each supported
	// word-count step.
	EntropySizeStep = 4
	// WordCountStep is the increment between supported mnemonic word counts.
	WordCountStep = 3
	// MinWordCount is the shortest supported mnemonic length in words.
	MinWordCount = 12
	// MaxWordCount is the longest supported mnemonic length in words.
	MaxWordCount = 24
)

var (
	//go:embed english.txt
	english    []byte
	value2word = bytes.Fields(english)
	word2value = generateWord2Value()
)

func generateWord2Value() map[string]uint32 {
	result := make(map[string]uint32)
	for value, word := range value2word {
		result[string(word)] = uint32(value)
	}
	return result
}

// GenerateMnemonic validates wordCount, reads the required entropy from
// entropyReader, and encodes it as a space-separated mnemonic from the BIP-39
// English wordlist.
func GenerateMnemonic(entropyReader io.Reader, wordCount int) ([]byte, error) {
	if wordCount%WordCountStep != 0 || wordCount < MinWordCount || wordCount > MaxWordCount {
		return nil, InvalidWordCountError{WordCount: wordCount}
	}
	entropy := make([]byte, wordCount/WordCountStep*EntropySizeStep)
	if _, err := io.ReadFull(entropyReader, entropy); err != nil {
		return nil, fmt.Errorf("failed to read entropy: %w", err)
	}
	sentence := make([][]byte, 0, wordCount)
	remain, shift := uint32(0), 0
	for i := range entropy {
		remain, shift = (remain<<BitsPerByte)|uint32(entropy[i]), shift+BitsPerByte
		for shift >= BitsPerWord {
			reducedShift := shift - BitsPerWord
			sentence = append(sentence, value2word[remain>>reducedShift])
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}
	checksumBits := wordCount / WordCountStep
	checksum := uint32(hashx.Sha256Sum(entropy)[0] >> (BitsPerByte - checksumBits))
	sentence = append(sentence, value2word[(remain<<checksumBits)|checksum])
	return bytes.Join(sentence, []byte(" ")), nil
}

// MnemonicToSeed collapses whitespace, validates the mnemonic against the
// English wordlist and checksum, and derives the 64-byte PBKDF2-HMAC-SHA512
// seed with salt "mnemonic"+the NFKD-normalized passphrase and 2048 iterations.
func MnemonicToSeed(mnemonic, passphrase []byte) ([]byte, error) {
	sentence := bytes.Fields(mnemonic)
	wordCount := len(sentence)
	if wordCount%WordCountStep != 0 || wordCount < MinWordCount || wordCount > MaxWordCount {
		return nil, InvalidWordCountError{WordCount: wordCount}
	}
	entropy := make([]byte, 0, wordCount/WordCountStep*EntropySizeStep)
	remain, shift := uint32(0), 0
	for _, word := range sentence {
		value, exist := word2value[string(word)]
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
	checksumBits := wordCount / WordCountStep
	checksum := uint32(hashx.Sha256Sum(entropy)[0] >> (BitsPerByte - checksumBits))
	if remain != checksum {
		return nil, ChecksumMismatchError{Checksum: remain, WantChecksum: checksum}
	}
	salt := slices.Concat([]byte("mnemonic"), norm.NFKD.Bytes(passphrase))
	return pbkdf2.Key(bytes.Join(sentence, []byte(" ")), salt, 2048, 64, sha512.New), nil
}
