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
	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/hashx"
)

const (
	// purposeDefault selects BIP44 derivation.
	purposeDefault = 44
	// coinDefault selects the SLIP-44 coin type for Sui.
	coinDefault = 784
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
	// secretDefault prints an address instead of a Bech32-encoded Sui private key by default.
	secretDefault = false
)

// backend holds user-configurable derivation path segments and output mode. Set
// change or index to -1 to omit trailing hardened derivation-path segments.
type backend struct {
	// account is the account number before hardening, so it must stay below the
	// hardened boundary.
	account uint32
	// change selects the optional trailing hardened chain; set it to -1 to omit
	// this segment and any following derivation-path segments.
	change int32
	// index selects the child within the chosen change chain; set it to -1 to omit
	// this final derivation-path segment.
	index int32
	// secret requests a Bech32-encoded Sui private key instead of a Sui address.
	secret bool
}

// backendDefault returns the default Sui BIP44 derivation settings with change
// and index enabled at zero.
func backendDefault() *backend {
	return &backend{
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints a Sui address or Bech32-encoded
// Sui private key.
func NewCmd() *cobra.Command {
	b := backendDefault()
	cmd := &cobra.Command{
		Use:   "sui",
		Short: "Derive a Sui address or Bech32-encoded Sui private key from a mnemonic",
		Example: "  dpass mnemonic | dpass sui\n" +
			"  dpass mnemonic | dpass sui --change -1 --index -1\n" +
			"  dpass mnemonic | dpass sui --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, "Derivation path account index")
	cmd.Flags().Int32Var(&b.change, "change", changeDefault, fmt.Sprintf(
		"Derivation path change segment (set to %d to omit change and index)", changeIgnore))
	cmd.Flags().Int32Var(&b.index, "index", indexDefault, fmt.Sprintf(
		"Derivation path address index (set to %d to omit this segment)", indexIgnore))
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault,
		"output Bech32-encoded Sui private key instead of address")
	return cmd
}

// checkFlags validates CLI derivation-path inputs and Sui-specific omission rules.
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

// runE reads a mnemonic from stdin and prints a Sui address or Bech32-encoded
// Sui private key.
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

// getResult derives the SLIP-0010 Ed25519 private key at m/44'/784'/account'
// with optional /change' and /index' suffixes, and formats a Sui address or
// Bech32-encoded Sui private key.
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
		return encodeSk(privateKey[:ed25519.SeedSize])
	}
	return pkToAddress(privateKey[ed25519.SeedSize:]), nil
}

// encodeSk prepends scheme flag 0x00 to the 32-byte seed and Bech32-encodes the
// result as a Sui private key with the suiprivkey prefix.
func encodeSk(sk []byte) (string, error) {
	out, err := bech32.Encode("suiprivkey", nil, slices.Concat([]byte{0}, sk))
	if err != nil {
		return "", fmt.Errorf("failed to encode private key: %w", err)
	}
	return out, nil
}

// pkToAddress prepends scheme flag 0x00 to the pubkey, hashes the payload with
// BLAKE2b-256, and hex-encodes the result with a 0x prefix.
func pkToAddress(pk []byte) string {
	return "0x" + hex.EncodeToString(hashx.Blake2b256Sum(slices.Concat([]byte{0}, pk)))
}
