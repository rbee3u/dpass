// Package dogecoin provides a CLI command for deriving Dogecoin addresses and
// WIF-encoded private keys from mnemonics.
package dogecoin

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bip32"
	"github.com/rbee3u/dpass/pkg/bip39"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

const (
	// purposeDefault selects BIP44 derivation.
	purposeDefault = 44
	// coinDefault selects the SLIP-44 coin type for Dogecoin.
	coinDefault = 3
	// accountDefault selects the first account.
	accountDefault = 0
	// changeDefault selects the external address chain.
	changeDefault = 0
	// indexDefault selects the first address index.
	indexDefault = 0
	// secretDefault prints an address instead of a WIF-encoded private key by default.
	secretDefault = false
)

// backend holds user-configurable derivation path segments and output mode.
type backend struct {
	// account is the account number before hardening, so it must stay below the
	// hardened boundary.
	account uint32
	// change selects the trailing chain, typically 0 for external receive
	// addresses and 1 for internal change addresses.
	change uint32
	// index selects the child within the chosen change chain.
	index uint32
	// secret requests a WIF-encoded private key instead of a Dogecoin address.
	secret bool
}

// backendDefault returns the default Dogecoin BIP44 derivation settings.
func backendDefault() *backend {
	return &backend{
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints a Dogecoin address or
// WIF-encoded private key.
func NewCmd() *cobra.Command {
	b := backendDefault()
	cmd := &cobra.Command{
		Use:   "dogecoin",
		Short: "Derive a Dogecoin address or WIF-encoded private key from a mnemonic",
		Example: "  dpass mnemonic | dpass dogecoin\n" +
			"  dpass mnemonic | dpass dogecoin --account 1 --index 2\n" +
			"  dpass mnemonic | dpass dogecoin --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, "Derivation path account index")
	cmd.Flags().Uint32Var(&b.change, "change", changeDefault, "Derivation path change segment (0 external, 1 internal)")
	cmd.Flags().Uint32Var(&b.index, "index", indexDefault, "Derivation path address index")
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault,
		"output WIF-encoded private key instead of address")
	return cmd
}

// checkFlags validates CLI derivation-path inputs and Dogecoin-specific constraints.
func (b *backend) checkFlags() error {
	if b.account >= bip32.FirstHardenedChild {
		return invalidAccountError{Got: b.account}
	}
	if b.change != 0 && b.change != 1 {
		return invalidChangeError{Got: b.change}
	}
	if b.index >= bip32.FirstHardenedChild {
		return invalidIndexError{Got: b.index}
	}
	return nil
}

// runE reads a mnemonic from stdin and prints a Dogecoin address or WIF-encoded private key.
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
// m/44'/3'/account'/change/index and formats a Dogecoin address or WIF-encoded
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
		b.change,
		b.index,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive private key: %w", err)
	}
	if b.secret {
		return encodeSk(sk), nil
	}
	return pkToAddress(secp256k1.S256().ScalarBaseMult(sk)), nil
}

// encodeSk adds the Dogecoin compressed WIF payload (0x9e prefix, 0x01 suffix)
// and Base58Check-encodes the result.
func encodeSk(sk []byte) string {
	data := slices.Concat([]byte{158}, sk, []byte{1})
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

// pkToAddress compresses the pubkey, hashes it with HASH160, and
// Base58Check-encodes the result as a P2PKH address.
func pkToAddress(x, y *big.Int) string {
	data := make([]byte, 33)
	data[0] = 2
	x.FillBytes(data[1:33])
	data[0] += byte(y.Bit(0))
	pkHash := hashx.RipeMD160Sum(hashx.Sha256Sum(data))
	data = slices.Concat([]byte{30}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}
