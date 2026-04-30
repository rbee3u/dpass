// Package bitcoin provides a CLI command for deriving Bitcoin addresses and
// WIF-encoded private keys from mnemonics.
package bitcoin

import (
	"fmt"
	"io"
	"math/big"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bech32"
	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

const (
	// purposeDefault selects BIP84 native SegWit derivation by default.
	purposeDefault = purpose84
	// purpose44 selects legacy P2PKH derivation.
	purpose44 = 44
	// purpose49 selects nested SegWit P2WPKH-in-P2SH derivation.
	purpose49 = 49
	// purpose84 selects native SegWit P2WPKH derivation.
	purpose84 = 84
	// purpose86 selects Taproot P2TR derivation.
	purpose86 = 86

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
	// purpose selects the purpose path segment and, therefore, the address format for
	// m/purpose'/0'/account'/change/index.
	purpose uint32
	// account is the account number before hardening, so it must stay below the
	// hardened boundary.
	account uint32
	// change selects the trailing chain, typically 0 for external receive addresses
	// and 1 for internal change addresses.
	change uint32
	// index selects the child within the chosen change chain.
	index uint32
	// secret requests a WIF-encoded private key instead of a Bitcoin address.
	secret bool
}

// backendDefault returns the default Bitcoin mainnet derivation settings.
func backendDefault() *backend {
	return &backend{
		purpose: purposeDefault,
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints the derived Bitcoin address or
// WIF-encoded private key.
func NewCmd() *cobra.Command {
	b := backendDefault()
	cmd := &cobra.Command{
		Use:   "bitcoin",
		Short: "Derive a Bitcoin address or WIF-encoded private key from a mnemonic",
		Example: "  dpass mnemonic | dpass bitcoin\n" +
			"  dpass mnemonic | dpass bitcoin --purpose 49 --account 1 --index 2\n" +
			"  dpass mnemonic | dpass bitcoin --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.purpose, "purpose", purposeDefault, fmt.Sprintf(
		"Derivation path purpose segment: one of %d (legacy P2PKH) / %d (nested SegWit) / %d (native SegWit) / %d (Taproot BIP86)",
		purpose44, purpose49, purpose84, purpose86))
	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, "Derivation path account index")
	cmd.Flags().Uint32Var(&b.change, "change", changeDefault, "Derivation path change segment (0 external, 1 internal)")
	cmd.Flags().Uint32Var(&b.index, "index", indexDefault, "Derivation path address index")
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault,
		"output WIF-encoded private key instead of address")
	return cmd
}

// checkFlags validates CLI derivation-path inputs and Bitcoin-specific constraints.
func (b *backend) checkFlags() error {
	allowed := []uint32{purpose44, purpose49, purpose84, purpose86}
	if !slices.Contains(allowed, b.purpose) {
		return invalidPurposeError{Got: b.purpose, Allowed: allowed}
	}
	if b.account >= bip3x.FirstHardenedChild {
		return invalidAccountError{Got: b.account}
	}
	if b.change != 0 && b.change != 1 {
		return invalidChangeError{Got: b.change}
	}
	if b.index >= bip3x.FirstHardenedChild {
		return invalidIndexError{Got: b.index}
	}
	return nil
}

// runE reads a mnemonic from stdin and prints the derived Bitcoin address or
// WIF-encoded private key.
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
		return fmt.Errorf("failed to write result to stdout: %w", err)
	}
	return nil
}

// getResult derives the BIP32 secp256k1 private key at
// m/purpose'/0'/account'/change/index and formats a Bitcoin address or WIF-encoded
// private key.
func (b *backend) getResult(mnemonic string) (string, error) {
	if err := b.checkFlags(); err != nil {
		return "", err
	}
	seed, err := bip3x.MnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	sk, err := bip3x.Secp256k1DeriveSk(seed, []uint32{
		b.purpose + bip3x.FirstHardenedChild,
		0 + bip3x.FirstHardenedChild,
		b.account + bip3x.FirstHardenedChild,
		b.change,
		b.index,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive child private key: %w", err)
	}
	var pkOrPkHash []byte
	switch b.purpose {
	case purpose44, purpose49, purpose84:
		sk, pkOrPkHash = prepareClassic(sk)
	default:
		sk, pkOrPkHash = prepareTaproot(sk)
	}
	if b.secret {
		return encodeSk(sk), nil
	}
	switch b.purpose {
	case purpose44:
		return pkHashToAddress44(pkOrPkHash)
	case purpose49:
		return pkHashToAddress49(pkOrPkHash)
	case purpose84:
		return pkHashToAddress84(pkOrPkHash)
	default:
		return pkToAddress86(pkOrPkHash)
	}
}

// prepareClassic returns the original child private key plus HASH160(compressed pubkey).
func prepareClassic(sk []byte) ([]byte, []byte) {
	x, y := secp256k1.S256().ScalarBaseMult(sk)
	pk := make([]byte, 33)
	pk[0] = 2
	x.FillBytes(pk[1:33])
	pk[0] += byte(y.Bit(0))
	pkHash := hashx.RipeMD160Sum(hashx.Sha256Sum(pk))
	return sk, pkHash
}

// prepareTaproot normalizes the internal key to even Y, applies the TapTweak hash,
// and returns the tweaked private key plus x-only output key.
func prepareTaproot(sk0Bytes []byte) ([]byte, []byte) {
	curve := secp256k1.S256()
	sk := new(big.Int).SetBytes(sk0Bytes)
	x, y := curve.ScalarBaseMult(sk0Bytes)
	if y.Bit(0) == 1 {
		sk.Sub(curve.N, sk)
		y.Sub(curve.P, y)
		y.Mod(y, curve.P)
	}
	xBytes := make([]byte, 32)
	x.FillBytes(xBytes)
	tagHash := hashx.Sha256Sum([]byte("TapTweak"))
	tBytes := hashx.Sha256Sum(slices.Concat(tagHash, tagHash, xBytes))
	t := new(big.Int).SetBytes(tBytes)
	if t.Cmp(curve.N) >= 0 {
		panic("taproot: tweak exceeds curve order")
	}
	osk := new(big.Int).Add(sk, t)
	osk.Mod(osk, curve.N)
	if osk.Sign() == 0 {
		panic("taproot: output private key is zero")
	}
	oskBytes := make([]byte, 32)
	osk.FillBytes(oskBytes)
	ox, _ := curve.ScalarBaseMult(oskBytes)
	opkBytes := make([]byte, 32)
	ox.FillBytes(opkBytes)
	return oskBytes, opkBytes
}

// encodeSk adds the Bitcoin mainnet compressed WIF payload and Base58Check-encodes
// the result.
func encodeSk(sk []byte) string {
	data := slices.Concat([]byte{128}, sk, []byte{1})
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

// pkHashToAddress44 prefixes HASH160(compressed pubkey) with version 0x00 and
// Base58Check-encodes the result as a legacy P2PKH address.
func pkHashToAddress44(pkHash []byte) (string, error) {
	data := slices.Concat([]byte{0}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest)), nil
}

// pkHashToAddress49 wraps HASH160(compressed pubkey) in P2WPKH-in-P2SH, hashes the
// script, and Base58Check-encodes the result.
func pkHashToAddress49(pkHash []byte) (string, error) {
	pkScript := slices.Concat([]byte{0, 20}, pkHash)
	data := slices.Concat([]byte{5}, hashx.RipeMD160Sum(hashx.Sha256Sum(pkScript)))
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest)), nil
}

// pkHashToAddress84 encodes HASH160(compressed pubkey) as a witness version 0
// Bech32 address for BIP84.
func pkHashToAddress84(pkHash []byte) (string, error) {
	address, err := bech32.EncodeSegWit("bc", 0, pkHash)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %w", err)
	}
	return address, nil
}

// pkToAddress86 encodes the tweaked x-only pubkey as a witness version 1 Bech32m
// address for BIP86.
func pkToAddress86(pk []byte) (string, error) {
	address, err := bech32.EncodeSegWit("bc", 1, pk)
	if err != nil {
		return "", fmt.Errorf("failed to encode address: %w", err)
	}
	return address, nil
}
