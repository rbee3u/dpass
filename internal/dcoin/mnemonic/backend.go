package mnemonic

import (
	"fmt"
	"os"

	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/spf13/cobra"
)

type backend struct {
	size int
}

func backendDefault() *backend {
	return &backend{size: bip3x.EntropyBitsMax}
}

func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{Use: "mnemonic", Args: cobra.NoArgs, RunE: backend.runE}
	cmd.Flags().IntVarP(&backend.size, "size", "s", bip3x.EntropyBitsMax, fmt.Sprintf(
		"size is the number of entropy bits, must be a multiple of %v and within [%v, %v]",
		bip3x.EntropyBitsStep, bip3x.EntropyBitsMin, bip3x.EntropyBitsMax))
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	entropy, err := bip3x.CreateEntropyRandomly(b.size)
	if err != nil {
		return fmt.Errorf("failed to create entropy randomly: %w", err)
	}
	mnemonic, err := bip3x.EntropyToMnemonic(entropy)
	if err != nil {
		return fmt.Errorf("failed to convert entropy to mnemonic: %w", err)
	}
	if _, err := os.Stdout.WriteString(mnemonic); err != nil {
		return fmt.Errorf("failed to write mnemonic: %w", err)
	}
	return nil
}
