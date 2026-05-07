// Package ethereum provides a CLI command for deriving Ethereum addresses and
// hex-encoded private keys from mnemonics.
package ethereum

import (
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/bip32"
	"github.com/rbee3u/dpass/pkg/bip39"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

const (
	// purposeDefault selects BIP44 derivation.
	purposeDefault = 44
	// coinDefault selects the SLIP-44 coin type for Ethereum.
	coinDefault = 60
	// accountDefault selects the first account.
	accountDefault = 0
	// indexDefault selects the first address index.
	indexDefault = 0
	// secretDefault prints an address instead of a hex-encoded private key by default.
	secretDefault = false
)

// backend holds user-configurable derivation path segments and output mode.
type backend struct {
	// account is the account number before hardening, so it must stay below the
	// hardened boundary.
	account uint32
	// index selects the child within the fixed external chain.
	index uint32
	// secret requests a hex-encoded private key instead of an Ethereum address.
	secret bool
}

// backendDefault returns the default Ethereum BIP44 derivation settings.
func backendDefault() *backend {
	return &backend{
		account: accountDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints an Ethereum address or a
// hex-encoded private key.
func NewCmd() *cobra.Command {
	b := backendDefault()
	cmd := &cobra.Command{
		Use:   "ethereum",
		Short: "Derive an Ethereum address or hex-encoded private key from a mnemonic",
		Example: "  dpass mnemonic | dpass ethereum\n" +
			"  dpass mnemonic | dpass ethereum --account 1 --index 2\n" +
			"  dpass mnemonic | dpass ethereum --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, "Derivation path account index")
	cmd.Flags().Uint32Var(&b.index, "index", indexDefault, "Derivation path address index")
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault,
		"output hex-encoded private key instead of address")
	return cmd
}

// checkFlags validates CLI derivation-path inputs and Ethereum-specific constraints.
func (b *backend) checkFlags() error {
	if b.account >= bip32.FirstHardenedChild {
		return invalidAccountError{Got: b.account}
	}
	if b.index >= bip32.FirstHardenedChild {
		return invalidIndexError{Got: b.index}
	}
	return nil
}

// runE reads a mnemonic from stdin and prints an Ethereum address or a
// hex-encoded private key.
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

// getResult derives the BIP32 secp256k1 private key at
// m/44'/60'/account'/0/index and formats an Ethereum address or a hex-encoded
// private key.
func (b *backend) getResult(mnemonic string) (string, error) {
	if err := b.checkFlags(); err != nil {
		return "", err
	}
	seed, err := bip39.MnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}
	sk, err := bip32.Secp256k1DeriveSk(seed, []uint32{
		purposeDefault + bip32.FirstHardenedChild,
		coinDefault + bip32.FirstHardenedChild,
		b.account + bip32.FirstHardenedChild,
		0,
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

// pkToAddress hashes the uncompressed pubkey with Keccak-256, applies the
// EIP-55 checksum to the hex payload, and returns the 0x-prefixed address.
func pkToAddress(x, y *big.Int) string {
	pk := make([]byte, 64)
	x.FillBytes(pk[:32])
	y.FillBytes(pk[32:])
	data := []byte(hex.EncodeToString(hashx.Keccak256Sum(pk)[12:]))
	digest := hashx.Keccak256Sum(data)
	for i := range data {
		if ((digest[i/2]>>(4-i%2*4))&0b1000) != 0 && unicode.IsLower(rune(data[i])) {
			data[i] = byte(unicode.ToUpper(rune(data[i])))
		}
	}
	return "0x" + string(data)
}
