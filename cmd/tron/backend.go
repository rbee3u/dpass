// Package tron provides a CLI command for deriving Tron addresses and secret keys from mnemonics.
package tron

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

// Derivation defaults and output mode for the Tron command.
const (
	// purposeDefault selects BIP44 derivation.
	purposeDefault = 44
	// coinDefault selects the SLIP-44 coin type for Tron.
	coinDefault = 195
	// accountDefault selects the first account.
	accountDefault = 0
	// changeDefault selects the external address chain.
	changeDefault = 0
	// indexDefault selects the first address index.
	indexDefault = 0
	// secretDefault prints an address instead of a secret key by default.
	secretDefault = false
)

// backend holds BIP44 path segments for Tron (secp256k1).
type backend struct {
	// purpose is the hardened BIP44 purpose segment.
	purpose uint32
	// coin is the hardened SLIP-44 coin type for Tron.
	coin uint32
	// account is the hardened account segment in the derivation path.
	account uint32
	// change is the first unhardened trailing path component.
	change uint32
	// index is the second unhardened trailing path component.
	index uint32
	// secret requests hex-encoded secp256k1 secret; else Base58Check address with 0x41 prefix.
	secret bool
}

// backendDefault fixes Tron BIP44 coin type 195.
func backendDefault() *backend {
	return &backend{
		purpose: purposeDefault,
		coin:    coinDefault,
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints a Tron address or hex-encoded secret key.
func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{
		Use:   "tron",
		Short: "Derive a Tron address or private key from a mnemonic",
		Example: "  dpass mnemonic | dpass tron\n" +
			"  dpass mnemonic | dpass tron --account 1 --index 2\n" +
			"  dpass mnemonic | dpass tron --secret",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}
	cmd.Flags().Uint32Var(&backend.account, "account", accountDefault, "BIP44 account index")
	cmd.Flags().Uint32Var(&backend.change, "change", changeDefault, "BIP44 change segment")
	cmd.Flags().Uint32Var(&backend.index, "index", indexDefault, "BIP44 address index")
	cmd.Flags().BoolVar(&backend.secret, "secret", secretDefault,
		"output private key (hex) instead of address")

	return cmd
}

// checkArguments rejects path parts that would be invalid as unhardened CLI integers.
func (b *backend) checkArguments() error {
	if b.purpose >= bip3x.FirstHardenedChild {
		return invalidPurposeError{Got: b.purpose}
	}

	if b.coin >= bip3x.FirstHardenedChild {
		return invalidCoinError{Got: b.coin}
	}

	if b.account >= bip3x.FirstHardenedChild {
		return invalidAccountError{Got: b.account}
	}

	if b.change >= bip3x.FirstHardenedChild {
		return invalidChangeError{Got: b.change}
	}

	if b.index >= bip3x.FirstHardenedChild {
		return invalidIndexError{Got: b.index}
	}

	return nil
}

// runE reads a mnemonic and prints a Tron address or hex secret key.
func (b *backend) runE(_ *cobra.Command, _ []string) error {
	mnemonic, err := helper.ReadMnemonic()
	if err != nil {
		return err
	}

	result, err := b.getResult(mnemonic)
	if err != nil {
		return err
	}

	if _, err := os.Stdout.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}

	return nil
}

// getResult derives the BIP32 secp256k1 key and formats Tron address or hex secret.
func (b *backend) getResult(mnemonic string) (string, error) {
	if err := b.checkArguments(); err != nil {
		return "", err
	}

	seed, err := bip3x.MnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}

	sk, err := bip3x.Secp256k1DeriveSk(seed, []uint32{
		b.purpose + bip3x.FirstHardenedChild,
		b.coin + bip3x.FirstHardenedChild,
		b.account + bip3x.FirstHardenedChild,
		b.change,
		b.index,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive private key: %w", err)
	}

	if b.secret {
		return hex.EncodeToString(sk), nil
	}

	return pkToAddress(secp256k1.S256().ScalarBaseMult(sk)), nil
}

// pkToAddress builds the 0x41-prefixed Keccak-20-byte payload with double-SHA256 checksum.
func pkToAddress(x, y *big.Int) string {
	pk := make([]byte, 64)
	x.FillBytes(pk[:32])
	y.FillBytes(pk[32:])
	data := slices.Concat([]byte{'A'}, hashx.Keccak256Sum(pk)[12:])
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]

	return base58.Encode(slices.Concat(data, digest))
}
