// Package mnemonic provides a CLI command for generating BIP-39 mnemonics.
package mnemonic

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/bip39"
)

type backend struct {
	wordCount int
	writer    io.Writer
}

// NewCmd generates a random BIP-39 mnemonic and prints it to stdout.
func NewCmd() *cobra.Command {
	b := &backend{writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "mnemonic",
		Short: "Generate a random BIP-39 mnemonic",
		Example: "  dpass mnemonic\n" +
			"  dpass mnemonic --word-count 12",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().IntVar(&b.wordCount, "word-count", bip39.MaxWordCount,
		"number of words in the generated mnemonic: 12, 15, 18, 21, or 24")
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	mnemonic, err := bip39.GenerateMnemonic(rand.Reader, b.wordCount)
	if err != nil {
		return fmt.Errorf("failed to generate mnemonic: %w", err)
	}
	if _, err := b.writer.Write(mnemonic); err != nil {
		return fmt.Errorf("failed to write mnemonic: %w", err)
	}
	return nil
}
