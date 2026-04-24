// Package solana provides a CLI command for deriving Solana keys from mnemonics.
package solana

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/helper"
)

// Derivation constants, optional path sentinels, and output mode for the Solana command.
const (
	// purposeDefault selects BIP44 derivation.
	purposeDefault = 44
	// coinDefault selects the SLIP-44 coin type for Solana.
	coinDefault = 501
	// accountDefault selects the first account.
	accountDefault = 0
	// changeDefault keeps the optional change segment enabled at zero by default.
	changeDefault = 0
	// changeIgnore omits the change segment and any following path segments.
	changeIgnore = -1
	// indexDefault selects the first address index.
	indexDefault = 0
	// indexIgnore omits the final address-index segment.
	indexIgnore = -1
	// secretDefault prints the public key instead of the private key by default.
	secretDefault = false
)

// backend holds user-configurable derivation path segments; change/index -1 omits trailing hardened levels.
type backend struct {
	// account is the hardened account segment in the derivation path.
	account uint32
	// change uses -1 to omit itself and the index suffix from the path.
	change int32
	// index uses -1 to omit the final hardened address index.
	index int32
	// secret requests the full Base58-encoded Ed25519 keypair seed+pub; else pubkey only.
	secret bool
}

// backendDefault fixes Solana BIP44 coin type 501 without optional path suffixes.
func backendDefault() *backend {
	return &backend{
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints a Base58 secret key or public key.
func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{
		Use:   "solana",
		Short: "Derive a Solana address or private key from a mnemonic",
		Example: "  dpass mnemonic | dpass solana\n" +
			"  dpass mnemonic | dpass solana --change -1 --index -1\n" +
			"  dpass mnemonic | dpass solana --secret",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}
	cmd.Flags().Uint32Var(&backend.account, "account", accountDefault, "BIP44 account index")
	cmd.Flags().Int32Var(&backend.change, "change", changeDefault, fmt.Sprintf(
		"BIP44 change segment (set to %d to omit change and index)", changeIgnore))
	cmd.Flags().Int32Var(&backend.index, "index", indexDefault, fmt.Sprintf(
		"BIP44 address index (set to %d to omit this segment)", indexIgnore))
	cmd.Flags().BoolVar(&backend.secret, "secret", secretDefault,
		"output private key (Base58 keypair) instead of address")

	return cmd
}

// checkArguments validates hardened constraints and the change/index ignore pairing rules.
func (b *backend) checkArguments() error {
	if b.account >= bip3x.FirstHardenedChild {
		return invalidAccountError{Got: b.account}
	}

	if b.change < changeIgnore {
		return invalidChangeError{Got: b.change}
	}

	if b.index < indexIgnore {
		return invalidIndexError{Got: b.index}
	}

	if b.change == changeIgnore && b.index != indexIgnore {
		return invalidIndexError{Got: b.index, RequireIgnore: true}
	}

	return nil
}

// runE reads a mnemonic and prints a Solana secret or public key in Base58.
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

// getResult derives SLIP-0010 Ed25519 material and encodes the requested key form.
func (b *backend) getResult(mnemonic string) (string, error) {
	if err := b.checkArguments(); err != nil {
		return "", err
	}

	seed, err := bip3x.MnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}

	path := []uint32{
		purposeDefault + bip3x.FirstHardenedChild,
		coinDefault + bip3x.FirstHardenedChild,
		b.account + bip3x.FirstHardenedChild,
	}
	if b.change != changeIgnore {
		path = append(path, uint32(b.change)+bip3x.FirstHardenedChild)
	}

	if b.index != indexIgnore {
		path = append(path, uint32(b.index)+bip3x.FirstHardenedChild)
	}

	sk, err := bip3x.Ed25519DeriveSk(seed, path)
	if err != nil {
		return "", fmt.Errorf("failed to derive private key: %w", err)
	}

	privateKey := ed25519.NewKeyFromSeed(sk)
	if b.secret {
		return base58.Encode(privateKey), nil
	}

	return base58.Encode(privateKey[ed25519.SeedSize:]), nil
}
