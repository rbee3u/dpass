package mnemonic

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip39"
)

func RegisterBackend(cmd *cobra.Command) {
	instance := new(backend)
	cmd.RunE = instance.runE

	cmd.Flags().IntVarP(&instance.size, "size", "s", sizeDefault, fmt.Sprintf(
		"entropy bits, must be within [%v, %v] and a multiple of %v", sizeMin, sizeMax, sizeStep))
}

const (
	sizeDefault = sizeMax
	sizeMin     = 128
	sizeMax     = 256
	sizeStep    = 32
)

type backend struct {
	size int
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	entropy, err := createEntropyRandomly(b.size)
	if err != nil {
		return fmt.Errorf("failed to create entropy randomly: %w", err)
	}

	mnemonic, err := newMnemonicFromEntropy(entropy)
	if err != nil {
		return fmt.Errorf("failed to new mnemonic from entropy: %w", err)
	}

	if _, err := os.Stdout.WriteString(mnemonic); err != nil {
		return fmt.Errorf("failed to write mnemonic: %w", err)
	}

	return nil
}

func createEntropyRandomly(size int) ([]byte, error) {
	entropy, err := bip39.NewEntropy(size)
	if err != nil {
		return nil, fmt.Errorf("failed to new entropy: %w", err)
	}

	return entropy, nil
}

func newMnemonicFromEntropy(entropy []byte) (string, error) {
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to new mnemonic: %w", err)
	}

	return mnemonic, nil
}
