package tron

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip32"
)

const (
	purposeDefault = 44
	coinDefault    = 195
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

func Register(cmd *cobra.Command) *cobra.Command {
	b := backendDefault()
	cmd.RunE = b.runE

	cmd.Flags().Uint32Var(&b.index, "index", indexDefault, fmt.Sprintf(
		"index is the number of address (default %v)", indexDefault))

	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault, fmt.Sprintf(
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

	sk, err := crypto.ToECDSA(key.Key)
	if err != nil {
		return "", fmt.Errorf("failed to convert key: %w", err)
	}

	if b.secret {
		return hex.EncodeToString(crypto.FromECDSA(sk)), nil
	}

	return pkToAddress(sk.PublicKey), nil
}

func pkToAddress(pk ecdsa.PublicKey) string {
	const magicByte = 0x41
	data := append([]byte{magicByte}, crypto.PubkeyToAddress(pk).Bytes()...)

	digest := sha256.Sum256(data)
	digest = sha256.Sum256(digest[:])

	return base58.Encode(append(data, digest[:4]...))
}
