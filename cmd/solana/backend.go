// Package solana provides a CLI command for deriving Solana addresses and
// Base58-encoded Ed25519 keypairs from mnemonics. On Solana, an address is the public key.
package solana

import (
	"crypto/ed25519"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bip3x"
)

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
	// secretDefault prints an address instead of a Base58-encoded Ed25519 keypair by default.
	secretDefault = false
)

// backend holds user-configurable derivation path segments and output mode. Set
// change or index to -1 to omit trailing hardened derivation-path segments.
type backend struct {
	// account is the account number before hardening, so it must stay below the
	// hardened boundary.
	account uint32
	// change selects the optional trailing hardened chain; set it to -1 to omit this
	// segment and any following derivation-path segments.
	change int32
	// index selects the child within the chosen change chain; set it to -1 to omit
	// this final derivation-path segment.
	index int32
	// secret requests a Base58-encoded Ed25519 keypair instead of a Solana address.
	secret bool
}

// backendDefault returns the default Solana BIP44 derivation settings with change
// and index enabled at zero.
func backendDefault() *backend {
	return &backend{
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints a Solana address or Base58-encoded
// Ed25519 keypair.
func NewCmd() *cobra.Command {
	b := backendDefault()
	cmd := &cobra.Command{
		Use:   "solana",
		Short: "Derive a Solana address or Base58-encoded Ed25519 keypair from a mnemonic",
		Example: "  dpass mnemonic | dpass solana\n" +
			"  dpass mnemonic | dpass solana --change -1 --index -1\n" +
			"  dpass mnemonic | dpass solana --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, "Derivation path account index")
	cmd.Flags().Int32Var(&b.change, "change", changeDefault, fmt.Sprintf(
		"Derivation path change segment (set to %d to omit change and index)", changeIgnore))
	cmd.Flags().Int32Var(&b.index, "index", indexDefault, fmt.Sprintf(
		"Derivation path address index (set to %d to omit this segment)", indexIgnore))
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault,
		"output Base58-encoded Ed25519 keypair instead of address")
	return cmd
}

// checkFlags validates CLI derivation-path inputs and Solana-specific omission rules.
func (b *backend) checkFlags() error {
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

// runE reads a mnemonic from stdin and prints a Solana address or Base58-encoded
// Ed25519 keypair.
func (b *backend) runE(_ *cobra.Command, _ []string) error {
	mnemonic, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read mnemonic: %w", err)
	}
	result, err := b.getResult(string(mnemonic))
	if err != nil {
		return err
	}
	if _, err := os.Stdout.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}
	return nil
}

// getResult derives the SLIP-0010 Ed25519 private key at m/44'/501'/account' with
// optional /change' and /index' suffixes, and formats a Solana address or
// Base58-encoded Ed25519 keypair.
func (b *backend) getResult(mnemonic string) (string, error) {
	if err := b.checkFlags(); err != nil {
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
