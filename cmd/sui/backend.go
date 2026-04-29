// Package sui provides a CLI command for deriving Sui addresses and secret keys from mnemonics.
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

// Derivation constants, optional path sentinels, and output mode for the Sui command.
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
	// secretDefault prints an address instead of a secret key by default.
	secretDefault = false
)

// backend mirrors Solana-style user-configurable trailing path levels.
type backend struct {
	// account is the hardened account segment in the derivation path.
	account uint32
	// change uses -1 to omit itself and the index suffix from the path.
	change int32
	// index uses -1 to omit the final hardened address index.
	index int32
	// secret requests suiprivkey Bech32; else a 0x-prefixed Blake2b-256 address.
	secret bool
}

// backendDefault targets Sui coin type 784 with default account/change/index.
func backendDefault() *backend {
	return &backend{
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints a Sui address or suiprivkey Bech32 secret.
func NewCmd() *cobra.Command {
	b := backendDefault()
	cmd := &cobra.Command{
		Use:   "sui",
		Short: "Derive a Sui address or private key from a mnemonic",
		Example: "  dpass mnemonic | dpass sui\n" +
			"  dpass mnemonic | dpass sui --change -1 --index -1\n" +
			"  dpass mnemonic | dpass sui --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, "BIP44 account index")
	cmd.Flags().Int32Var(&b.change, "change", changeDefault, fmt.Sprintf(
		"BIP44 change segment (set to %d to omit change and index)", changeIgnore))
	cmd.Flags().Int32Var(&b.index, "index", indexDefault, fmt.Sprintf(
		"BIP44 address index (set to %d to omit this segment)", indexIgnore))
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault,
		"output private key (Bech32 suiprivkey) instead of address")
	return cmd
}

// checkArguments mirrors Solana rules: -1 change drops suffixes; index must stay consistent.
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

// runE reads a mnemonic and prints a Sui address or suiprivkey secret encoding.
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

// getResult derives Ed25519 per SLIP-0010 and formats Sui-specific encodings.
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
		secret, err := encodeSecretKey(privateKey[:ed25519.SeedSize])
		if err != nil {
			return "", err
		}
		return secret, nil
	}
	return pkToAddress(privateKey[ed25519.SeedSize:]), nil
}

// encodeSecretKey Bech32-encodes the 32-byte seed with scheme tag suiprivkey (flag byte 0).
func encodeSecretKey(sk []byte) (string, error) {
	key, err := bech32.Encode("suiprivkey", nil, slices.Concat([]byte{0}, sk))
	if err != nil {
		return "", fmt.Errorf("failed to encode suiprivkey: %w", err)
	}
	return key, nil
}

// pkToAddress hashes flag 0x00||pubkey with BLAKE2b-256 and hex-encodes with 0x prefix.
func pkToAddress(pk []byte) string {
	return "0x" + hex.EncodeToString(hashx.Blake2b256Sum(slices.Concat([]byte{0}, pk)))
}
