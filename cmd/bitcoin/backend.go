// Package bitcoin provides a CLI command for deriving Bitcoin addresses and WIF keys from mnemonics.
package bitcoin

import (
	"errors"
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

// Purpose and derivation defaults for the Bitcoin command.
const (
	// purposeDefault selects native SegWit derivation by default.
	purposeDefault = purpose84
	// purpose44 selects legacy P2PKH derivation.
	purpose44 = 44
	// purpose49 selects nested SegWit P2WPKH-in-P2SH derivation.
	purpose49 = 49
	// purpose84 selects native SegWit P2WPKH derivation.
	purpose84 = 84
	// purpose86 selects Taproot P2TR derivation.
	purpose86 = 86

	// coinDefault selects the BIP44 coin type for Bitcoin mainnet.
	coinDefault = 0
	// magicPrivateKeyMainNet prefixes mainnet WIF payloads.
	magicPrivateKeyMainNet = 0x80
	// magicPubKeyHashMainNet prefixes legacy P2PKH addresses.
	magicPubKeyHashMainNet = 0x00
	// magicScriptHashMainNet prefixes nested SegWit P2SH addresses.
	magicScriptHashMainNet = 0x05
	// bech32HRPMainNet is the HRP for native SegWit and Taproot addresses.
	bech32HRPMainNet = "bc"

	// accountDefault selects the first account.
	accountDefault = 0
	// changeDefault selects the external address chain.
	changeDefault = 0
	// indexDefault selects the first address index.
	indexDefault = 0
	// secretDefault prints an address instead of a WIF by default.
	secretDefault = false
)

// backend holds CLI flags that affect derivation and output encoding.
type backend struct {
	// purpose selects BIP44 (44), nested SegWit (49), native SegWit (84), or Taproot (86).
	purpose uint32
	// account is the hardened account segment in the derivation path.
	account uint32
	// change is the first unhardened trailing path component.
	change uint32
	// index is the second unhardened trailing path component.
	index uint32
	// secret requests WIF output instead of a payment address.
	secret bool
}

// backendDefault returns CLI defaults matching Bitcoin mainnet and native SegWit.
func backendDefault() *backend {
	return &backend{
		purpose: purposeDefault,
		account: accountDefault,
		change:  changeDefault,
		index:   indexDefault,
		secret:  secretDefault,
	}
}

// NewCmd reads a mnemonic from stdin and prints a derived address or WIF.
func NewCmd() *cobra.Command {
	b := backendDefault()
	cmd := &cobra.Command{
		Use:   "bitcoin",
		Short: "Derive a Bitcoin address or private key from a mnemonic",
		Example: "  dpass mnemonic | dpass bitcoin\n" +
			"  dpass mnemonic | dpass bitcoin --purpose 49 --account 1 --index 2\n" +
			"  dpass mnemonic | dpass bitcoin --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.purpose, "purpose", purposeDefault, fmt.Sprintf(
		"BIP purpose: one of %d (legacy P2PKH) / %d (nested SegWit) / %d (native SegWit) / %d (Taproot BIP86)",
		purpose44, purpose49, purpose84, purpose86))
	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, "BIP44 account index")
	cmd.Flags().Uint32Var(&b.change, "change", changeDefault, "BIP44 change segment")
	cmd.Flags().Uint32Var(&b.index, "index", indexDefault, "BIP44 address index")
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault,
		"output private key (WIF) instead of address")
	return cmd
}

// checkArguments validates CLI flags without mutating backend state.
func (b *backend) checkArguments() error {
	if err := b.checkPurpose(); err != nil {
		return err
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

// checkPurpose validates the selected BIP purpose.
func (b *backend) checkPurpose() error {
	switch b.purpose {
	case purpose44:
	case purpose49:
	case purpose84:
	case purpose86:
		return nil
	default:
		return invalidPurposeError{
			Got:     b.purpose,
			Allowed: []uint32{purpose44, purpose49, purpose84, purpose86},
		}
	}
	return nil
}

// resolveLegacyPurpose returns the legacy address encoder for non-Taproot purposes.
func (b *backend) resolveLegacyPurpose() (func([]byte) (string, error), error) {
	switch b.purpose {
	case purpose44:
		return pkHashToAddress44, nil
	case purpose49:
		return pkHashToAddress49, nil
	case purpose84:
		return pkHashToAddress84, nil
	default:
		return nil, invalidPurposeError{
			Got:     b.purpose,
			Allowed: []uint32{purpose44, purpose49, purpose84},
		}
	}
}

// runE reads a mnemonic from stdin and prints the derived address or WIF.
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

// getResult derives the secp256k1 key along the BIP32 path and formats output per flags.
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
		coinDefault + bip3x.FirstHardenedChild,
		b.account + bip3x.FirstHardenedChild,
		b.change,
		b.index,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive private key: %w", err)
	}
	if b.purpose == purpose86 {
		return b.taprootResult(sk)
	}
	convert, err := b.resolveLegacyPurpose()
	if err != nil {
		return "", err
	}
	if b.secret {
		return b.skToWIF(sk), nil
	}
	x, y := secp256k1.S256().ScalarBaseMult(sk)
	return b.pkToAddress(x, y, convert)
}

func (b *backend) taprootResult(sk []byte) (string, error) {
	taprootKey, err := deriveTaprootKey(sk)
	if err != nil {
		return "", err
	}
	if b.secret {
		return b.skToWIF(taprootKey.secret), nil
	}
	address, err := bech32.EncodeSegWit(bech32HRPMainNet, 1, taprootKey.outputKey)
	if err != nil {
		return "", fmt.Errorf("failed to encode taproot address: %w", err)
	}
	return address, nil
}

// skToWIF encodes the secret with the Bitcoin mainnet compressed WIF payload and Base58Check.
func (b *backend) skToWIF(sk []byte) string {
	data := slices.Concat([]byte{magicPrivateKeyMainNet}, sk, []byte{1})
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

// pkToAddress hashes the compressed pubkey and encodes the result per purpose.
func (b *backend) pkToAddress(
	x, y *big.Int,
	convert func([]byte) (string, error),
) (string, error) {
	data := make([]byte, 33)
	data[0] = 2
	x.FillBytes(data[1:33])
	data[0] += byte(y.Bit(0))
	pkHash := hashx.RipeMD160Sum(hashx.Sha256Sum(data))
	return convert(pkHash)
}

// pkHashToAddress44 builds a P2PKH Base58Check address (BIP44 legacy).
func pkHashToAddress44(pkHash []byte) (string, error) {
	data := slices.Concat([]byte{magicPubKeyHashMainNet}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest)), nil
}

// pkHashToAddress49 wraps the pubkey hash in P2WPKH-in-P2SH and Base58Check-encodes it.
func pkHashToAddress49(pkHash []byte) (string, error) {
	pkScript := slices.Concat([]byte{0, 20}, pkHash)
	data := slices.Concat([]byte{magicScriptHashMainNet}, hashx.RipeMD160Sum(hashx.Sha256Sum(pkScript)))
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest)), nil
}

// pkHashToAddress84 Bech32-encodes witness version 0 with the pubkey hash (BIP84).
func pkHashToAddress84(pkHash []byte) (string, error) {
	address, err := bech32.EncodeSegWit(bech32HRPMainNet, 0, pkHash)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32 address: %w", err)
	}
	return address, nil
}

type taprootKey struct {
	secret    []byte
	outputKey []byte
}

// deriveTaprootKey returns the BIP86 tweaked private key and output key.
func deriveTaprootKey(sk []byte) (taprootKey, error) {
	curve := secp256k1.S256()
	d := new(big.Int).SetBytes(sk)
	x, y := curve.ScalarBaseMult(sk)
	if y.Bit(0) == 1 {
		d.Sub(curve.N, d)
		y.Sub(curve.P, y)
		y.Mod(y, curve.P)
	}

	internalKey := make([]byte, 32)
	x.FillBytes(internalKey)

	tagHash := hashx.Sha256Sum([]byte("TapTweak"))
	tweakBytes := hashx.Sha256Sum(slices.Concat(tagHash, tagHash, internalKey))
	tweak := new(big.Int).SetBytes(tweakBytes)
	if tweak.Cmp(curve.N) >= 0 {
		return taprootKey{}, errors.New("failed to tweak taproot key: tweak exceeds curve order")
	}

	tx, ty := curve.ScalarBaseMult(tweakBytes)
	outputX, outputY := curve.Add(x, y, tx, ty)

	secret := new(big.Int).Add(d, tweak)
	secret.Mod(secret, curve.N)
	if secret.Sign() == 0 {
		return taprootKey{}, errors.New("failed to tweak taproot key: tweaked private key is zero")
	}
	if outputX.Sign() == 0 && outputY.Sign() == 0 {
		return taprootKey{}, errors.New("failed to tweak taproot key: output key is point at infinity")
	}

	outputKey := make([]byte, 32)
	outputX.FillBytes(outputKey)
	secretBytes := make([]byte, 32)
	secret.FillBytes(secretBytes)
	return taprootKey{secret: secretBytes, outputKey: outputKey}, nil
}
