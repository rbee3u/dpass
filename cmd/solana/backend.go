// Package solana provides a CLI command for deriving Solana addresses and
// Base58-encoded Ed25519 keypairs from mnemonics. On Solana, an address is the
// public key.
package solana

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bip32"
	"github.com/rbee3u/dpass/pkg/bip39"
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

// NewCmd reads a mnemonic from stdin and prints a Solana address or
// Base58-encoded Ed25519 keypair.
func NewCmd() *cobra.Command {
	b := &backend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "solana",
		Short: "Derive a Solana address or Base58-encoded Ed25519 keypair from a mnemonic",
		Example: "  dpass mnemonic | dpass solana\n" +
			"  dpass mnemonic | dpass solana --change -1 --index -1\n" +
			"  dpass mnemonic | dpass solana --secret",
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
	cmd.Flags().BoolVar(&b.secret, "secret", false, "output Base58-encoded Ed25519 keypair instead of address")
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
		501 + bip32.FirstHardenedChild,
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
		result = encodeSk(privateKey)
	} else {
		result = pkToAddress(privateKey[ed25519.SeedSize:])
	}
	if _, err := b.writer.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}
	return nil
}

func encodeSk(sk []byte) string {
	return base58.Encode(sk)
}

func pkToAddress(pk []byte) string {
	return base58.Encode(pk)
}
