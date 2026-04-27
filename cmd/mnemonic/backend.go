// Package mnemonic provides a CLI command for generating BIP-39 mnemonics.
package mnemonic

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

// backend stores requested entropy size in bits (BIP-39 constraints).
type backend struct {
	// size is the requested entropy length in bits before mnemonic encoding.
	size int
}

// backendDefault targets the longest supported mnemonic (256-bit entropy).
func backendDefault() *backend {
	return &backend{size: bip3x.EntropyBitsMax}
}

// NewCmd generates random entropy and prints a BIP-39 mnemonic to stdout.
func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{
		Use:   "mnemonic",
		Short: "Generate a random BIP-39 mnemonic",
		Example: "  dpass mnemonic\n" +
			"  dpass mnemonic --size 128",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}
	cmd.Flags().IntVarP(&backend.size, "size", "s", bip3x.EntropyBitsMax, fmt.Sprintf(
		"entropy size in bits: multiple of %d within [%d, %d]",
		bip3x.EntropyBitsStep, bip3x.EntropyBitsMin, bip3x.EntropyBitsMax))

	return cmd
}

// runE emits a random BIP-39 mnemonic for the configured entropy size.
func (b *backend) runE(_ *cobra.Command, _ []string) error {
	result, err := b.getResult()
	if err != nil {
		return err
	}

	if _, err := os.Stdout.WriteString(result); err != nil {
		return fmt.Errorf("failed to write mnemonic: %w", err)
	}

	return nil
}

// getResult generates a BIP-39 mnemonic for the configured entropy size.
func (b *backend) getResult() (string, error) {
	entropy, err := bip3x.CreateEntropyRandomly(b.size)
	if err != nil {
		return "", fmt.Errorf("failed to generate random entropy: %w", err)
	}

	mnemonic, err := bip3x.EntropyToMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}

	return mnemonic, nil
}
