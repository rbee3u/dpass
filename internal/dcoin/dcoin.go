package dcoin

import (
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rbee3u/dpass/third_party/github.com/tyler-smith/go-bip32"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160" //nolint:staticcheck
	"golang.org/x/crypto/sha3"
)

var (
	//go:embed english.txt
	english    string
	value2word = strings.Fields(english)
	word2value = make(map[string]uint32)
)

func init() {
	for value, word := range value2word {
		word2value[word] = uint32(value)
	}
}

func ReadMnemonic() (string, error) {
	mnemonic, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read mnemonic: %w", err)
	}

	return strings.Join(strings.Fields(string(mnemonic)), " "), nil
}

func EntropyToMnemonic(entropy []byte) (string, error) {
	entropySize := len(entropy) * 8
	if entropySize%32 != 0 || entropySize < 128 || entropySize > 256 {
		return "", fmt.Errorf("invalid entropy size: %v", entropySize)
	}

	digestSize := entropySize / 32
	sentence := make([]string, 0, digestSize*3)

	remain, shift := uint32(0), 0

	for i := range entropy {
		remain, shift = (remain<<8)|uint32(entropy[i]), shift+8
		for reducedShift := shift - 11; reducedShift >= 0; reducedShift = shift - 11 {
			sentence = append(sentence, value2word[remain>>reducedShift])
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}

	digest := uint32(Sha256Sum(entropy)[0] >> (8 - digestSize))
	sentence = append(sentence, value2word[(remain<<digestSize)|digest])

	return strings.Join(sentence, " "), nil
}

func MnemonicToSeed(mnemonic string, password string) ([]byte, error) {
	sentence := strings.Fields(mnemonic)

	sentenceSize := len(sentence) * 11
	if sentenceSize%33 != 0 || sentenceSize < 132 || sentenceSize > 264 {
		return nil, fmt.Errorf("invalid sentence size: %v", sentenceSize)
	}

	digestSize := sentenceSize / 33
	entropy := make([]byte, 0, digestSize*4)

	remain, shift := uint32(0), 0

	for i := range sentence {
		value, ok := word2value[sentence[i]]
		if !ok {
			return nil, fmt.Errorf("invalid word: %s", sentence[i])
		}

		remain, shift = (remain<<11)|value, shift+11
		for reducedShift := shift - 8; reducedShift > 0; reducedShift = shift - 8 {
			entropy = append(entropy, byte(remain>>reducedShift))
			remain, shift = remain&((1<<reducedShift)-1), reducedShift
		}
	}

	digest := uint32(Sha256Sum(entropy)[0] >> (8 - digestSize))
	if digest != remain {
		return nil, fmt.Errorf("invalid digest: %v", digest)
	}

	return pbkdf2.Key([]byte(strings.Join(sentence, " ")), []byte("mnemonic"+password), 2048, 64, sha512.New), nil
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
