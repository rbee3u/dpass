// Package tron provides a CLI command for deriving Tron addresses and
// hex-encoded private keys from mnemonics.
package tron

import (
	"encoding/hex"
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
	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

const maxInputBytes = 1024

type backend struct {
	account uint32
	index   uint32
	secret  bool
	reader  io.Reader
	writer  io.StringWriter
}

// NewCmd reads a mnemonic from stdin and prints a Tron address or hex-encoded
// private key.
func NewCmd() *cobra.Command {
	b := &backend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "tron",
		Short: "Derive a Tron address or hex-encoded private key from a mnemonic",
		Example: "  dpass mnemonic | dpass tron\n" +
			"  dpass mnemonic | dpass tron --account 1 --index 2\n" +
			"  dpass mnemonic | dpass tron --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", 0, "derivation path account")
	cmd.Flags().Uint32Var(&b.index, "index", 0, "derivation path index")
	cmd.Flags().BoolVar(&b.secret, "secret", false, "output hex-encoded private key instead of address")
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	if b.account >= bip32.FirstHardenedChild {
		return invalidAccountError{account: b.account}
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
		return fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}
	sk, err := bip32.Secp256k1DeriveSk(seed, []uint32{
		44 + bip32.FirstHardenedChild,
		195 + bip32.FirstHardenedChild,
		b.account + bip32.FirstHardenedChild,
		0,
		b.index,
	})
	if err != nil {
		return fmt.Errorf("failed to derive private key: %w", err)
	}
	var result string
	if b.secret {
		result = encodeSk(sk)
	} else {
		result = pkToAddress(secp256k1.S256().ScalarBaseMult(sk))
	}
	if _, err := b.writer.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}
	return nil
}

func encodeSk(sk []byte) string {
	return hex.EncodeToString(sk)
}

func pkToAddress(x, y *big.Int) string {
	pk := make([]byte, 64)
	x.FillBytes(pk[:32])
	y.FillBytes(pk[32:])
	data := slices.Concat([]byte{65}, hashx.Keccak256Sum(pk)[12:])
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}
