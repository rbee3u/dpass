package dogecoin

import (
	"errors"
	"fmt"
	"os"

	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/rbee3u/dpass/third_party/github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/rbee3u/dpass/third_party/github.com/mr-tron/base58"
	"github.com/rbee3u/dpass/third_party/github.com/tyler-smith/go-bip32"
	"github.com/spf13/cobra"
)

const (
	purposeDefault = 44
	coinDefault    = 3
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
	cmd := &cobra.Command{Use: "dogecoin", Args: cobra.NoArgs, RunE: backend.runE}

	cmd.Flags().Uint32Var(&backend.index, "index", indexDefault, fmt.Sprintf(
		"index is the number of address (default %v)", indexDefault))
	cmd.Flags().BoolVar(&backend.secret, "secret", secretDefault, fmt.Sprintf(
		"show secret instead of address (default %t)", secretDefault))

	return cmd
}

func (b *backend) checkArguments() error {
	if b.purpose >= bip32.FirstHardenedChild {
		return errInvalidPurpose
	}

	if b.coin >= bip32.FirstHardenedChild {
		return errInvalidCoin
	}

	if b.account >= bip32.FirstHardenedChild {
		return errInvalidAccount
	}

	if b.change >= bip32.FirstHardenedChild {
		return errInvalidChange
	}

	if b.index >= bip32.FirstHardenedChild {
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

	seed, err := dcoin.MnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}

	key, err := dcoin.SeedToKey(seed, []uint32{
		bip32.FirstHardenedChild + b.purpose,
		bip32.FirstHardenedChild + b.coin,
		bip32.FirstHardenedChild + b.account,
		b.change,
		b.index,
	})
	if err != nil {
		return "", fmt.Errorf("failed to convert seed to key: %w", err)
	}

	if b.secret {
		return b.skToWIF(secp256k1.PrivKeyFromBytes(key.Key)), nil
	}

	return b.pkToAddress(secp256k1.PrivKeyFromBytes(key.Key).PubKey()), nil
}

//nolint:gomnd
func (b *backend) skToWIF(sk *secp256k1.PrivateKey) string {
	data := make([]byte, 0, 38)
	data = append(data, 0x9e)
	data = append(data, sk.Serialize()...)
	data = append(data, 1)
	data = append(data, dcoin.Sha256Sum(dcoin.Sha256Sum(data))[:4]...)

	return base58.Encode(data)
}

//nolint:gomnd
func (b *backend) pkToAddress(pk *secp256k1.PublicKey) string {
	data := make([]byte, 0, 25)
	data = append(data, 0x1e)
	data = append(data, dcoin.RipeMD160Sum(dcoin.Sha256Sum(pk.SerializeCompressed()))...)
	data = append(data, dcoin.Sha256Sum(dcoin.Sha256Sum(data))[:4]...)

	return base58.Encode(data)
}
