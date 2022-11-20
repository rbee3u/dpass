package solana

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/rbee3u/dpass/third_party/github.com/mr-tron/base58"
	"github.com/rbee3u/dpass/third_party/github.com/tyler-smith/go-bip32"
	"github.com/spf13/cobra"
)

const (
	purposeDefault = 44
	coinDefault    = 501
	accountDefault = 0
	changeDefault  = 0
	secretDefault  = false

	secretSize = 32
)

var (
	errInvalidPurpose = errors.New("invalid purpose")
	errInvalidCoin    = errors.New("invalid coin")
	errInvalidAccount = errors.New("invalid account")
	errInvalidChange  = errors.New("invalid change")

	errNonHardenedChild = errors.New("non hardened child")
)

type backend struct {
	purpose uint32
	coin    uint32
	account uint32
	change  uint32
	secret  bool
}

func backendDefault() *backend {
	return &backend{
		purpose: purposeDefault,
		coin:    coinDefault,
		account: accountDefault,
		change:  changeDefault,
		secret:  secretDefault,
	}
}

func Register(cmd *cobra.Command) *cobra.Command {
	b := backendDefault()
	cmd.RunE = b.runE

	cmd.Flags().Uint32Var(&b.account, "account", accountDefault, fmt.Sprintf(
		"account is the number of address (default %v)", accountDefault))

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

	key, err := seedToKey(seed, []uint32{
		bip32.FirstHardenedChild + b.purpose,
		bip32.FirstHardenedChild + b.coin,
		bip32.FirstHardenedChild + b.account,
		bip32.FirstHardenedChild + b.change,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive key from mnemonic: %w", err)
	}

	privateKey := ed25519.NewKeyFromSeed(key)

	if b.secret {
		return base58.Encode(privateKey), nil
	}

	return base58.Encode(privateKey[ed25519.SeedSize:]), nil
}

func seedToKey(seed []byte, path []uint32) ([]byte, error) {
	hash := hmac.New(sha512.New, []byte("ed25519 seed"))
	hash.Write(seed)
	digest := hash.Sum(nil)

	for i := range path {
		if path[i] < bip32.FirstHardenedChild {
			return nil, errNonHardenedChild
		}

		hash = hmac.New(sha512.New, digest[secretSize:])
		hash.Write([]byte{0})
		hash.Write(digest[:secretSize])
		hash.Write(uint32ToBytes(path[i]))
		digest = hash.Sum(nil)
	}

	return digest[:secretSize], nil
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, unsafe.Sizeof(v))

	binary.BigEndian.PutUint32(b, v)

	return b
}
