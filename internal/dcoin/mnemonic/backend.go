package mnemonic

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/spf13/cobra"
)

const (
	sizeDefault = sizeMax
	sizeStep    = 32
	sizeMin     = 128
	sizeMax     = 256
)

type backend struct {
	size int
}

func backendDefault() *backend {
	return &backend{size: sizeDefault}
}

func Register(cmd *cobra.Command) *cobra.Command {
	b := backendDefault()
	cmd.RunE = b.runE

	cmd.Flags().IntVarP(&b.size, "size", "s", sizeDefault, fmt.Sprintf(
		"entropy bits, must be a multiple of %v and within [%v, %v]", sizeStep, sizeMin, sizeMax))

	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	entropy, err := createEntropyRandomly(b.size)
	if err != nil {
		return fmt.Errorf("failed to create entropy randomly: %w", err)
	}

	mnemonic, err := dcoin.EntropyToMnemonic(entropy)
	if err != nil {
		return fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}

	if _, err := os.Stdout.WriteString(mnemonic); err != nil {
		return fmt.Errorf("failed to write mnemonic: %w", err)
	}

	return nil
}

func createEntropyRandomly(size int) ([]byte, error) {
	if size%sizeStep != 0 || size < sizeMin || size > sizeMax {
		return nil, fmt.Errorf("invalid entropy size: %v", size)
	}

	entropy := make([]byte, size/8)
	_, _ = rand.Read(entropy)

	return entropy, nil
}
