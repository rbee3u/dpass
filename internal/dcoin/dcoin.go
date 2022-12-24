package dcoin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rbee3u/dpass/third_party/github.com/tyler-smith/go-bip32"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck
	"golang.org/x/crypto/sha3"
)

const (
	digestSizeMin = 4
	digestSizeMax = 8

	EntropySizeStep = 32
	EntropySizeMin  = digestSizeMin * EntropySizeStep
	EntropySizeMax  = digestSizeMax * EntropySizeStep

	sentenceSizeStep = 33
	sentenceSizeMin  = digestSizeMin * sentenceSizeStep
	sentenceSizeMax  = digestSizeMax * sentenceSizeStep

	byteSize = 8
	wordSize = 11
)

var (
	ErrInvalidSize   = errors.New("invalid size")
	errInvalidWord   = errors.New("invalid word")
	errInvalidDigest = errors.New("invalid digest")
)

var (
	//go:embed english.txt
	english    string
	value2word = strings.Fields(english) //nolint:gochecknoglobals
	word2value = generateWord2Value()    //nolint:gochecknoglobals
)

func generateWord2Value() map[string]uint32 {
	word2value := make(map[string]uint32)
	for value, word := range value2word {
		word2value[word] = uint32(value)
	}

	return word2value
}

func ReadMnemonic() (string, error) {
	mnemonic, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read mnemonic: %w", err)
	}

	return strings.Join(strings.Fields(string(mnemonic)), " "), nil
}

func CreateEntropyRandomly(entropySize int) ([]byte, error) {
	if err := checkEntropySize(entropySize); err != nil {
		return nil, err
	}

	entropy := make([]byte, entropySize/byteSize)
	_, _ = rand.Read(entropy)

	return entropy, nil
}

func checkEntropySize(entropySize int) error {
	if entropySize%EntropySizeStep != 0 {
		return fmt.Errorf("entropy size(%v) is not a multipule of %v: %w", entropySize, EntropySizeStep, ErrInvalidSize)
	}

	if entropySize < EntropySizeMin {
		return fmt.Errorf("entropy size(%v) is less than %v: %w", entropySize, EntropySizeMin, ErrInvalidSize)
	}

	if entropySize > EntropySizeMax {
		return fmt.Errorf("entropy size(%v) is greater than %v: %w", entropySize, EntropySizeMax, ErrInvalidSize)
	}

	return nil
}

func EntropyToMnemonic(entropy []byte) (string, error) {
	entropySize := len(entropy) * byteSize
	if err := checkEntropySize(entropySize); err != nil {
		return "", err
	}

	digestSize := entropySize / EntropySizeStep
	sentence := make([]string, 0, digestSize*sentenceSizeStep/wordSize)

	remain, shift := uint32(0), 0

	for i := range entropy {
		remain, shift = (remain<<byteSize)|uint32(entropy[i]), shift+byteSize
		for reducedShift := shift - wordSize; reducedShift >= 0; reducedShift = shift - wordSize {
			sentence = append(sentence, value2word[remain>>reducedShift])
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}

	digest := uint32(Sha256Sum(entropy)[0] >> (byteSize - digestSize))
	sentence = append(sentence, value2word[(remain<<digestSize)|digest])

	return strings.Join(sentence, " "), nil
}

func MnemonicToSeed(mnemonic string, password string) ([]byte, error) {
	sentence := strings.Fields(mnemonic)

	sentenceSize := len(sentence) * wordSize
	if err := checkSentenceSize(sentenceSize); err != nil {
		return nil, err
	}

	digestSize := sentenceSize / sentenceSizeStep
	entropy := make([]byte, 0, digestSize*EntropySizeStep/byteSize)

	remain, shift := uint32(0), 0

	for i := range sentence {
		value, ok := word2value[sentence[i]]
		if !ok {
			return nil, fmt.Errorf("word(%s) is not found: %w", sentence[i], errInvalidWord)
		}

		remain, shift = (remain<<wordSize)|value, shift+wordSize
		for reducedShift := shift - byteSize; reducedShift > 0; reducedShift = shift - byteSize {
			entropy = append(entropy, byte(remain>>reducedShift))
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}

	digest := uint32(Sha256Sum(entropy)[0] >> (byteSize - digestSize))
	if digest != remain {
		return nil, fmt.Errorf("digest(%v) does not match: %w", digest, errInvalidDigest)
	}

	salt := append([]byte("mnemonic"), password...)

	const (
		iterCount   = 2048
		lengthOfKey = 64
	)

	return pbkdf2.Key([]byte(strings.Join(sentence, " ")), salt, iterCount, lengthOfKey, sha512.New), nil
}

func checkSentenceSize(sentenceSize int) error {
	if sentenceSize%sentenceSizeStep != 0 {
		return fmt.Errorf("sentence size(%v) is not a multipule of %v: %w", sentenceSize, sentenceSizeStep, ErrInvalidSize)
	}

	if sentenceSize < sentenceSizeMin {
		return fmt.Errorf("sentence size(%v) is less than %v: %w", sentenceSize, sentenceSizeMin, ErrInvalidSize)
	}

	if sentenceSize > sentenceSizeMax {
		return fmt.Errorf("sentence size(%v) is greater than %v: %w", sentenceSize, sentenceSizeMax, ErrInvalidSize)
	}

	return nil
}

func SeedToKey(seed []byte, path []uint32) (*bip32.Key, error) {
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("failed to new master key: %w", err)
	}

	for i := range path {
		if key, err = key.NewChildKey(path[i]); err != nil {
			return nil, fmt.Errorf("failed to new child key: %w", err)
		}
	}

	return key, nil
}

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
