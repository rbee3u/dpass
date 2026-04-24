// Package dogecoin provides a CLI command for deriving Dogecoin addresses and WIF keys from mnemonics.
package dogecoin

import (
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

// Derivation defaults and output mode for the Dogecoin command.
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
	// secretDefault prints an address instead of a WIF by default.
	secretDefault = false
)

// backend holds derivation path segments and whether to output the raw secret key encoding.
type backend struct {
	// purpose is the hardened BIP44 purpose segment.
	purpose uint32
	// coin is the hardened SLIP-44 coin type for Dogecoin.
	coin uint32
	// account is the hardened account segment in the derivation path.
	account uint32
	// change is the first unhardened trailing path component.
	change uint32
	// index is the second unhardened trailing path component.
	index uint32
	// secret requests WIF instead of a P2PKH address.
	secret bool
}

// backendDefault returns the standard Dogecoin BIP44 path prefix defaults.
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

// NewCmd reads a mnemonic from stdin and prints a Dogecoin address or WIF.
func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{
		Use:   "dogecoin",
		Short: "Derive a Dogecoin address or private key from a mnemonic",
		Example: "  dpass mnemonic | dpass dogecoin\n" +
			"  dpass mnemonic | dpass dogecoin --account 1 --index 2\n" +
			"  dpass mnemonic | dpass dogecoin --secret",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}
	cmd.Flags().Uint32Var(&backend.account, "account", accountDefault, "BIP44 account index")
	cmd.Flags().Uint32Var(&backend.change, "change", changeDefault, "BIP44 change segment")
	cmd.Flags().Uint32Var(&backend.index, "index", indexDefault, "BIP44 address index")
	cmd.Flags().BoolVar(&backend.secret, "secret", secretDefault,
		"output private key (WIF) instead of address")

	return cmd
}

// checkArguments rejects path components that must not be hardened in this CLI.
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

// runE reads a mnemonic and prints a Dogecoin address or WIF.
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

// getResult derives the BIP32 secp256k1 key and formats address or WIF.
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
		return skToWIF(sk), nil
	}

	return pkToAddress(secp256k1.S256().ScalarBaseMult(sk)), nil
}

// skToWIF builds Dogecoin compressed WIF (0x9e prefix, 0x01 suffix) with Base58Check.
func skToWIF(sk []byte) string {
	data := slices.Concat([]byte{0x9e}, sk, []byte{1})
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]

	return base58.Encode(slices.Concat(data, digest))
}

// pkToAddress hashes a compressed pubkey and builds a P2PKH address.
func pkToAddress(x, y *big.Int) string {
	data := make([]byte, 33)
	data[0] = 2
	x.FillBytes(data[1:33])
	data[0] += byte(y.Bit(0))
	pkHash := hashx.RipeMD160Sum(hashx.Sha256Sum(data))

	return pkHashToAddress44(pkHash)
}

// pkHashToAddress44 Base58Check-encodes pubkey hash with Dogecoin mainnet P2PKH version 0x1e.
func pkHashToAddress44(pkHash []byte) string {
	data := slices.Concat([]byte{0x1e}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]

	return base58.Encode(slices.Concat(data, digest))
}
