package dcoin

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

func ReadMnemonic() (string, error) {
	mnemonic, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read mnemonic: %w", err)
	}

	return string(bytes.TrimSpace(mnemonic)), nil
}

func DeriveKeyFromMnemonic(mnemonic string, password string, path []uint32) (*bip32.Key, error) {
	return DeriveKeyFromSeed(bip39.NewSeed(mnemonic, password), path)
}

func DeriveKeyFromSeed(seed []byte, path []uint32) (*bip32.Key, error) {
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
