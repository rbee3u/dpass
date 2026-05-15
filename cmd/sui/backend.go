// Package sui provides a CLI command for deriving Sui addresses and
// Bech32-encoded Sui private keys with the suiprivkey prefix from mnemonics.
package sui

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/bech32"
	"github.com/rbee3u/dpass/pkg/bip32"
	"github.com/rbee3u/dpass/pkg/bip39"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/helper"
)

const (
	changeIgnore  int32 = -1
	indexIgnore   int32 = -1
	maxInputBytes       = 1024
)

type backend struct {
	account uint32
	change  int32
	index   int32
	secret  bool
	reader  io.Reader
	writer  io.StringWriter
}

// NewCmd reads a mnemonic from stdin and prints a Sui address or Bech32-encoded
// Sui private key.
func NewCmd() *cobra.Command {
	b := &backend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "sui",
		Short: "Derive a Sui address or Bech32-encoded Sui private key from a mnemonic",
		Example: "  dpass mnemonic | dpass sui\n" +
			"  dpass mnemonic | dpass sui --change -1 --index -1\n" +
			"  dpass mnemonic | dpass sui --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", 0, "derivation path account")
	cmd.Flags().Int32Var(&b.change, "change", 0, fmt.Sprintf(
		"derivation path change (set to %d to omit change and index)", changeIgnore,
	))
	cmd.Flags().Int32Var(&b.index, "index", 0, fmt.Sprintf(
		"derivation path index (set to %d to omit this segment)", indexIgnore,
	))
	cmd.Flags().BoolVar(&b.secret, "secret", false, "output Bech32-encoded Sui private key instead of address")
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	if b.account >= bip32.FirstHardenedChild {
		return invalidAccountError{account: b.account}
	}
	if b.change < changeIgnore {
		return invalidChangeError{change: b.change}
	}
	if b.index < indexIgnore {
		return invalidIndexError{index: b.index}
	}
	if b.change == changeIgnore && b.index != indexIgnore {
		return invalidIndexError{index: b.index, requireIgnore: true}
	}
	mnemonic, err := helper.ReadAllLimited(b.reader, maxInputBytes)
	if err != nil {
		return fmt.Errorf("failed to read mnemonic: %w", err)
	}
	seed, err := bip39.MnemonicToSeed(mnemonic, nil)
	if err != nil {
		return fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}
	path := []uint32{
		44 + bip32.FirstHardenedChild,
		784 + bip32.FirstHardenedChild,
		b.account + bip32.FirstHardenedChild,
	}
	if b.change != changeIgnore {
		path = append(path, uint32(b.change)+bip32.FirstHardenedChild)
	}
	if b.index != indexIgnore {
		path = append(path, uint32(b.index)+bip32.FirstHardenedChild)
	}
	sk, err := bip32.Ed25519DeriveSk(seed, path)
	if err != nil {
		return fmt.Errorf("failed to derive private key: %w", err)
	}
	privateKey := ed25519.NewKeyFromSeed(sk)
	var result string
	if b.secret {
		result, err = encodeSk(privateKey[:ed25519.SeedSize])
	} else {
		result = pkToAddress(privateKey[ed25519.SeedSize:])
	}
	if err != nil {
		return err
	}
	if _, err := b.writer.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}
	return nil
}

func encodeSk(sk []byte) (string, error) {
	return bech32.EncodeBech32("suiprivkey", nil, slices.Concat([]byte{0}, sk))
}

func pkToAddress(pk []byte) string {
	return "0x" + hex.EncodeToString(hashx.Blake2b256Sum(slices.Concat([]byte{0}, pk)))
}
