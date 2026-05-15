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
	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

const maxInputBytes = 1024

type backend struct {
	account uint32
	change  uint32
	index   uint32
	secret  bool
	reader  io.Reader
	writer  io.StringWriter
}

// NewCmd reads a mnemonic from stdin and prints a Dogecoin address or
// WIF-encoded private key.
func NewCmd() *cobra.Command {
	b := &backend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "dogecoin",
		Short: "Derive a Dogecoin address or WIF-encoded private key from a mnemonic",
		Example: "  dpass mnemonic | dpass dogecoin\n" +
			"  dpass mnemonic | dpass dogecoin --account 1 --index 2\n" +
			"  dpass mnemonic | dpass dogecoin --secret",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().Uint32Var(&b.account, "account", 0, "derivation path account")
	cmd.Flags().Uint32Var(&b.change, "change", 0, "derivation path change (0 external, 1 internal)")
	cmd.Flags().Uint32Var(&b.index, "index", 0, "derivation path index")
	cmd.Flags().BoolVar(&b.secret, "secret", false, "output WIF-encoded private key instead of address")
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
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
		return fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}
	sk, err := bip32.Secp256k1DeriveSk(seed, []uint32{
		44 + bip32.FirstHardenedChild,
		3 + bip32.FirstHardenedChild,
		b.account + bip32.FirstHardenedChild,
		b.change,
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
	data := slices.Concat([]byte{158}, sk, []byte{1})
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

func pkToAddress(x, y *big.Int) string {
	pk := make([]byte, 33)
	pk[0] = 2 + byte(y.Bit(0))
	x.FillBytes(pk[1:])
	pkHash := hashx.RipeMD160Sum(hashx.Sha256Sum(pk))
	data := slices.Concat([]byte{30}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}
