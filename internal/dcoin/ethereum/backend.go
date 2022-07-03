package ethereum

import (
	"errors"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip32"
)

func RegisterBackend(cmd *cobra.Command) {
	instance := new(backend)
	cmd.RunE = instance.runE

	cmd.Flags().StringVar(&instance.network, "network", networkDefault, fmt.Sprintf(
		"compatible network such as %q, %q or %q", networkETH, networkBSC, networkKCC))
	cmd.Flags().Uint32Var(&instance.index, "index", indexDefault, fmt.Sprintf(
		"index is the number of address (default %v)", indexDefault))
	cmd.Flags().BoolVar(&instance.secret, "secret", secretDefault, fmt.Sprintf(
		"show secret instead of address (default %t)", secretDefault))
}

var (
	errInvalidNetwork = errors.New("invalid network")
	errInvalidIndex   = errors.New("invalid index")
)

const (
	purpose44 = 44
)

const (
	networkDefault = networkETH
	networkETH     = "eth"
	networkBSC     = "bsc"
	networkKCC     = "kcc"
)

const (
	coinETH = 60
	coinBSC = 60
	coinKCC = 60
)

const (
	indexDefault = 0
)

const (
	secretDefault = false
)

type backend struct {
	purpose uint32
	network string
	coin    uint32
	account uint32
	change  uint32
	index   uint32
	secret  bool
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

	key, err := dcoin.DeriveKeyFromMnemonic(mnemonic, "", []uint32{
		bip32.FirstHardenedChild + b.purpose,
		bip32.FirstHardenedChild + b.coin,
		bip32.FirstHardenedChild + b.account,
		b.change,
		b.index,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive key from mnemonic: %w", err)
	}

	privateKey, err := crypto.ToECDSA(key.Key)
	if err != nil {
		return "", fmt.Errorf("failed to convert key: %w", err)
	}

	if b.secret {
		return hexutil.Encode(crypto.FromECDSA(privateKey)), nil
	}

	return crypto.PubkeyToAddress(privateKey.PublicKey).String(), nil
}

func (b *backend) checkArguments() error {
	b.purpose = purpose44

	switch b.network {
	case networkETH:
		b.coin = coinETH
	case networkBSC:
		b.coin = coinBSC
	case networkKCC:
		b.coin = coinKCC
	default:
		return errInvalidNetwork
	}

	if b.index >= bip32.FirstHardenedChild {
		return errInvalidIndex
	}

	return nil
}
