package ethereum

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"unicode"

	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/secp256k1"
	"github.com/spf13/cobra"
)

const (
	purposeDefault = 44
	coinDefault    = 60
	accountDefault = 0
	changeDefault  = 0
	indexDefault   = 0
	secretDefault  = false
)

var (
	errInvalidPurpose = errors.New("invalid purpose")
	errInvalidCoin    = errors.New("invalid coin")
	errInvalidAccount = errors.New("invalid account")
	errInvalidChange  = errors.New("invalid change")
	errInvalidIndex   = errors.New("invalid index")
)

type backend struct {
	purpose uint32
	coin    uint32
	account uint32
	change  uint32
	index   uint32
	secret  bool
}

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

func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{Use: "ethereum", Args: cobra.NoArgs, RunE: backend.runE}
	cmd.Flags().Uint32Var(&backend.index, "index", indexDefault, fmt.Sprintf(
		"index is the number of address (default %v)", indexDefault))
	cmd.Flags().BoolVar(&backend.secret, "secret", secretDefault, fmt.Sprintf(
		"show secret instead of address (default %t)", secretDefault))
	return cmd
}

func (b *backend) checkArguments() error {
	if b.purpose >= bip3x.FirstHardenedChild {
		return errInvalidPurpose
	}
	if b.coin >= bip3x.FirstHardenedChild {
		return errInvalidCoin
	}
	if b.account >= bip3x.FirstHardenedChild {
		return errInvalidAccount
	}
	if b.change >= bip3x.FirstHardenedChild {
		return errInvalidChange
	}
	if b.index >= bip3x.FirstHardenedChild {
		return errInvalidIndex
	}
	return nil
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	mnemonic, err := dcoin.ReadMnemonic()
	if err != nil {
		return fmt.Errorf("failed to read mnemonic: %w", err)
	}
	result, err := b.getResult(mnemonic)
	if err != nil {
		return fmt.Errorf("failed to get result: %w", err)
	}
	if _, err := os.Stdout.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}
	return nil
}

func (b *backend) getResult(mnemonic string) (string, error) {
	if err := b.checkArguments(); err != nil {
		return "", fmt.Errorf("failed to check arguments: %w", err)
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
		return "", fmt.Errorf("failed to derive sk: %w", err)
	}
	if b.secret {
		return hex.EncodeToString(sk), nil
	}
	return pkToAddress(secp256k1.S256().ScalarBaseMult(sk)), nil
}

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
