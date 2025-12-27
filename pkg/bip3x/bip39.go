package bip3x

import (
	"crypto/rand"
	"crypto/sha512"
	_ "embed"
	"fmt"
	"strings"

	"github.com/rbee3u/dpass/pkg/hashx"
	"golang.org/x/crypto/pbkdf2"
)

const (
	BitsPerByte = 8
	BitsPerWord = 11

	EntropyBitsStep = 32
	EntropyBitsMin  = 4 * EntropyBitsStep
	EntropyBitsMax  = 8 * EntropyBitsStep

	SentenceBitsStep = 33
	SentenceBitsMin  = 4 * SentenceBitsStep
	SentenceBitsMax  = 8 * SentenceBitsStep
)

type InvalidEntropyBitsError struct{ v int }

func (e InvalidEntropyBitsError) Error() string {
	return fmt.Sprintf("bip39: invalid entropy bits(%v)", e.v)
}

type InvalidSentenceBitsError struct{ v int }

func (e InvalidSentenceBitsError) Error() string {
	return fmt.Sprintf("bip39: invalid sentence bits(%v)", e.v)
}

type WordNotExistError struct{ v string }

func (e WordNotExistError) Error() string {
	return fmt.Sprintf("bip39: word(%s) not exist", e.v)
}

type DigestUnmatchedError struct{ v, u uint32 }

func (e DigestUnmatchedError) Error() string {
	return fmt.Sprintf("bip39: digest unmatched(%v != %v)", e.v, e.u)
}

var (
	//go:embed english.txt
	english    string
	value2word = strings.Fields(english)
	word2value = generateWord2Value()
)

func generateWord2Value() map[string]uint32 {
	word2value := make(map[string]uint32)
	for value, word := range value2word {
		word2value[word] = uint32(value)
	}
	return word2value
}

func CreateEntropyRandomly(entropySize int) ([]byte, error) {
	if entropySize%EntropyBitsStep != 0 || entropySize < EntropyBitsMin || entropySize > EntropyBitsMax {
		return nil, InvalidEntropyBitsError{v: entropySize}
	}
	entropy := make([]byte, entropySize/BitsPerByte)
	_, _ = rand.Read(entropy)
	return entropy, nil
}

func EntropyToMnemonic(entropy []byte) (string, error) {
	entropyBits := len(entropy) * BitsPerByte
	if entropyBits%EntropyBitsStep != 0 || entropyBits < EntropyBitsMin || entropyBits > EntropyBitsMax {
		return "", InvalidEntropyBitsError{v: entropyBits}
	}
	digestBits := entropyBits / EntropyBitsStep
	sentence := make([]string, 0, digestBits*SentenceBitsStep/BitsPerWord)
	remain, shift := uint32(0), 0
	for i := range entropy {
		remain, shift = (remain<<BitsPerByte)|uint32(entropy[i]), shift+BitsPerByte
		for reducedShift := shift - BitsPerWord; reducedShift >= 0; reducedShift = shift - BitsPerWord {
			sentence = append(sentence, value2word[remain>>reducedShift])
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}
	digest := uint32(hashx.Sha256Sum(entropy)[0] >> (BitsPerByte - digestBits))
	sentence = append(sentence, value2word[(remain<<digestBits)|digest])
	return strings.Join(sentence, " "), nil
}

func MnemonicToSeed(mnemonic string, password string) ([]byte, error) {
	sentence := strings.Fields(mnemonic)
	sentenceBits := len(sentence) * BitsPerWord
	if sentenceBits%SentenceBitsStep != 0 || sentenceBits < SentenceBitsMin || sentenceBits > SentenceBitsMax {
		return nil, InvalidSentenceBitsError{v: sentenceBits}
	}
	digestBits := sentenceBits / SentenceBitsStep
	entropy := make([]byte, 0, digestBits*EntropyBitsStep/BitsPerByte)
	remain, shift := uint32(0), 0
	for _, word := range sentence {
		value, exist := word2value[word]
		if !exist {
			return nil, WordNotExistError{v: word}
		}
		remain, shift = (remain<<BitsPerWord)|value, shift+BitsPerWord
		for reducedShift := shift - BitsPerByte; reducedShift > 0; reducedShift = shift - BitsPerByte {
			entropy = append(entropy, byte(remain>>reducedShift))
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}
	if digest := uint32(hashx.Sha256Sum(entropy)[0] >> (BitsPerByte - digestBits)); remain != digest {
		return nil, DigestUnmatchedError{v: remain, u: digest}
	}
	salt := append([]byte("mnemonic"), password...)
	return pbkdf2.Key([]byte(strings.Join(sentence, " ")), salt, 2048, 64, sha512.New), nil
}
