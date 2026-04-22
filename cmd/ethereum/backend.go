// Package ethereum provides a CLI command for deriving Ethereum addresses and secret keys from mnemonics.
package ethereum

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"unicode"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

// Derivation defaults and output mode for the Ethereum command.
const (
	// purposeDefault selects BIP44 derivation.
	purposeDefault = 44
	// coinDefault selects the SLIP-44 coin type for Ethereum.
	coinDefault = 60
	// accountDefault selects the first account.
	accountDefault = 0
	// changeDefault selects the external address chain.
	changeDefault = 0
	// indexDefault selects the first address index.
	indexDefault = 0
	// secretDefault prints an address instead of a secret key by default.
	secretDefault = false
)

// backend holds BIP44 path segments (purpose/coin fixed by defaults) and output mode.
type backend struct {
	// purpose is the hardened BIP44 purpose segment.
	purpose uint32
	// coin is the hardened SLIP-44 coin type for Ethereum.
	coin uint32
	// account is the hardened account segment in the derivation path.
	account uint32
	// change is the first unhardened trailing path component.
	change uint32
	// index is the second unhardened trailing path component.
	index uint32
	// secret requests hex-encoded secp256k1 secret instead of an EIP-55 address.
	secret bool
}

// backendDefault fixes Ethereum BIP44 coin type 60 with standard trailing indices.
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

// NewCmd reads a mnemonic from stdin and prints an EIP-55 address or hex-encoded secp256k1 key.
func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{
		Use:   "ethereum",
		Short: "Derive an Ethereum address or private key from a mnemonic",
		Example: "  dpass mnemonic | dpass ethereum\n" +
			"  dpass mnemonic | dpass ethereum --account 1 --index 2\n" +
			"  dpass mnemonic | dpass ethereum --secret",
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

// checkArguments rejects hardened flags that this CLI does not accept as plain integers.
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

// runE reads a mnemonic and prints an account address or hex secret key.
func (b *backend) runE(_ *cobra.Command, _ []string) error {
	mnemonic, err := helper.ReadMnemonic()
	if err != nil {
		return fmt.Errorf("failed to read mnemonic: %w", err)
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

// getResult derives the BIP32 key and formats EIP-55 or raw hex per flags.
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

// pkToAddress applies Keccak-256 to the uncompressed pubkey and EIP-55-mixes the hex.
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
