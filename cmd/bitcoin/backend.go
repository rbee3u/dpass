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
	"github.com/rbee3u/dpass/pkg/bip32"
	"github.com/rbee3u/dpass/pkg/bip39"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

const (
	purpose44     uint32 = 44
	purpose49     uint32 = 49
	purpose84     uint32 = 84
	purpose86     uint32 = 86
	maxInputBytes        = 1024
)

type backend struct {
	purpose uint32
	account uint32
	change  uint32
	index   uint32
	secret  bool
	reader  io.Reader
	writer  io.StringWriter
}

// NewCmd reads a mnemonic from stdin and prints the derived Bitcoin address or
// WIF-encoded private key.
func NewCmd() *cobra.Command {
	b := &backend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "bitcoin",
		Short: "Derive a Bitcoin address or WIF-encoded private key from a mnemonic",
		Example: "  dpass mnemonic | dpass bitcoin\n" +
			"  dpass mnemonic | dpass bitcoin --purpose 49 --account 1 --index 2\n" +
			"  dpass mnemonic | dpass bitcoin --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.purpose, "purpose", purpose84, fmt.Sprintf(
		"derivation path purpose: one of %d/%d/%d/%d", purpose44, purpose49, purpose84, purpose86,
	))
	cmd.Flags().Uint32Var(&b.account, "account", 0, "derivation path account")
	cmd.Flags().Uint32Var(&b.change, "change", 0, "derivation path change (0 external, 1 internal)")
	cmd.Flags().Uint32Var(&b.index, "index", 0, "derivation path index")
	cmd.Flags().BoolVar(&b.secret, "secret", false, "output WIF-encoded private key instead of address")
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	if b.purpose != purpose44 && b.purpose != purpose49 && b.purpose != purpose84 && b.purpose != purpose86 {
		return invalidPurposeError{account: b.purpose}
	}
	if b.account >= bip32.FirstHardenedChild {
		return invalidAccountError{account: b.account}
	}
	if b.change != 0 && b.change != 1 {
		return invalidChangeError{change: b.change}
	}
	if b.index >= bip32.FirstHardenedChild {
		return invalidIndexError{index: b.index}
	}
	mnemonic, err := helper.ReadAllLimited(b.reader, maxInputBytes)
	if err != nil {
		return fmt.Errorf("failed to read mnemonic: %w", err)
	}
	seed, err := bip39.MnemonicToSeed(mnemonic, nil)
	if err != nil {
		return fmt.Errorf("failed to derive seed from mnemonic: %w", err)
	}
	sk, err := bip32.Secp256k1DeriveSk(seed, []uint32{
		b.purpose + bip32.FirstHardenedChild,
		0 + bip32.FirstHardenedChild,
		b.account + bip32.FirstHardenedChild,
		b.change,
		b.index,
	})
	if err != nil {
		return fmt.Errorf("failed to derive child private key: %w", err)
	}
	var pkOrPkHash []byte
	switch b.purpose {
	case purpose44, purpose49, purpose84:
		sk, pkOrPkHash = prepareClassic(sk)
	default:
		sk, pkOrPkHash = prepareTaproot(sk)
	}
	var result string
	switch {
	case b.secret:
		result = encodeSk(sk)
	case b.purpose == purpose44:
		result = pkHashToAddress44(pkOrPkHash)
	case b.purpose == purpose49:
		result = pkHashToAddress49(pkOrPkHash)
	case b.purpose == purpose84:
		result, err = pkHashToAddress84(pkOrPkHash)
	default:
		result, err = pkToAddress86(pkOrPkHash)
	}
	if err != nil {
		return err
	}
	if _, err := b.writer.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result to stdout: %w", err)
	}
	return nil
}

func prepareClassic(sk []byte) ([]byte, []byte) {
	x, y := secp256k1.S256().ScalarBaseMult(sk)
	pk := make([]byte, 33)
	pk[0] = 2 + byte(y.Bit(0))
	x.FillBytes(pk[1:])
	pkHash := hashx.RipeMD160Sum(hashx.Sha256Sum(pk))
	return sk, pkHash
}

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

func encodeSk(sk []byte) string {
	data := slices.Concat([]byte{128}, sk, []byte{1})
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

func pkHashToAddress44(pkHash []byte) string {
	data := slices.Concat([]byte{0}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

func pkHashToAddress49(pkHash []byte) string {
	pkScript := slices.Concat([]byte{0, 20}, pkHash)
	data := slices.Concat([]byte{5}, hashx.RipeMD160Sum(hashx.Sha256Sum(pkScript)))
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

func pkHashToAddress84(pkHash []byte) (string, error) {
	return bech32.EncodeBech32("bc", []byte{0}, pkHash)
}

func pkToAddress86(pk []byte) (string, error) {
	return bech32.EncodeBech32m("bc", []byte{1}, pk)
}
