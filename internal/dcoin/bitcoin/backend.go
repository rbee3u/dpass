package bitcoin

import (
	"errors"
	"fmt"
	"math/big"
	"os"
	"slices"

	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bech32"
	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/third_party/github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/spf13/cobra"
)

const (
	purposeDefault = purpose84
	purpose44      = 44
	purpose49      = 49
	purpose84      = 84

	networkDefault       = networkMainNet
	networkMainNet       = "mainnet"
	networkRegressionNet = "regtest"
	networkTestNet3      = "testnet3"
	networkSimNet        = "simnet"

	coinMain = 0
	coinTest = 1

	accountDefault    = 0
	changeDefault     = 0
	indexDefault      = 0
	secretDefault     = false
	decompressDefault = false
)

var (
	errInvalidPurpose = errors.New("invalid purpose")
	errInvalidNetwork = errors.New("invalid network")
	errInvalidAccount = errors.New("invalid account")
	errInvalidChange  = errors.New("invalid change")
	errInvalidIndex   = errors.New("invalid index")
)

type backend struct {
	purpose         uint32
	convert         func([]byte) string
	network         string
	magicPrivateKey byte
	magicPubKeyHash byte
	magicScriptHash byte
	magicBech32HRP  string
	coin            uint32
	account         uint32
	change          uint32
	index           uint32
	secret          bool
	decompress      bool
}

func backendDefault() *backend {
	return &backend{
		purpose:    purposeDefault,
		network:    networkDefault,
		account:    accountDefault,
		change:     changeDefault,
		index:      indexDefault,
		secret:     secretDefault,
		decompress: decompressDefault,
	}
}

func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{Use: "bitcoin", Args: cobra.NoArgs, RunE: backend.runE}
	cmd.Flags().Uint32Var(&backend.purpose, "purpose", purposeDefault, fmt.Sprintf(
		"purpose must be %v, %v or %v", purpose44, purpose49, purpose84))
	cmd.Flags().StringVar(&backend.network, "network", networkDefault, fmt.Sprintf(
		"network must be %q, %q, %q or %q", networkMainNet, networkRegressionNet, networkTestNet3, networkSimNet))
	cmd.Flags().Uint32Var(&backend.index, "index", indexDefault, fmt.Sprintf(
		"index is the number of address (default %v)", indexDefault))
	cmd.Flags().BoolVar(&backend.secret, "secret", secretDefault, fmt.Sprintf(
		"show secret instead of address (default %t)", secretDefault))
	cmd.Flags().BoolVar(&backend.decompress, "decompress", decompressDefault, fmt.Sprintf(
		"compress the public key or not (default %t)", decompressDefault))
	return cmd
}

func (b *backend) checkArguments() error {
	if err := b.checkPurpose(); err != nil {
		return fmt.Errorf("failed to check purpose: %w", err)
	}
	if err := b.checkNetwork(); err != nil {
		return fmt.Errorf("failed to check network: %w", err)
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

func (b *backend) checkPurpose() error {
	switch b.purpose {
	case purpose44:
		b.convert = b.pkHashToAddress44
	case purpose49:
		b.convert = b.pkHashToAddress49
	case purpose84:
		b.convert = b.pkHashToAddress84
	default:
		return errInvalidPurpose
	}
	return nil
}

func (b *backend) checkNetwork() error {
	switch b.network {
	case networkMainNet:
		b.magicPrivateKey = 0x80
		b.magicPubKeyHash = 0x00
		b.magicScriptHash = 0x05
		b.magicBech32HRP = "bc"
		b.coin = coinMain
	case networkRegressionNet:
		b.magicPrivateKey = 0xef
		b.magicPubKeyHash = 0x6f
		b.magicScriptHash = 0xc4
		b.magicBech32HRP = "bcrt"
		b.coin = coinTest
	case networkTestNet3:
		b.magicPrivateKey = 0xef
		b.magicPubKeyHash = 0x6f
		b.magicScriptHash = 0xc4
		b.magicBech32HRP = "tb"
		b.coin = coinTest
	case networkSimNet:
		b.magicPrivateKey = 0x64
		b.magicPubKeyHash = 0x3f
		b.magicScriptHash = 0x7b
		b.magicBech32HRP = "sb"
		b.coin = coinTest
	default:
		return errInvalidNetwork
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
		return b.skToWIF(sk), nil
	}
	return b.pkToAddress(secp256k1.S256().ScalarBaseMult(sk)), nil
}

func (b *backend) skToWIF(sk []byte) string {
	data := slices.Concat([]byte{b.magicPrivateKey}, sk)
	if !b.decompress {
		data = append(data, 1)
	}
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

func (b *backend) pkToAddress(x, y *big.Int) string {
	var data []byte
	if !b.decompress {
		data = make([]byte, 33)
		data[0] = 2
		x.FillBytes(data[1:33])
		data[0] += byte(y.Bit(0))
	} else {
		data = make([]byte, 65)
		data[0] = 4
		x.FillBytes(data[1:33])
		y.FillBytes(data[33:65])
	}
	pkHash := hashx.RipeMD160Sum(hashx.Sha256Sum(data))
	return b.convert(pkHash)
}

func (b *backend) pkHashToAddress44(pkHash []byte) string {
	data := slices.Concat([]byte{b.magicPubKeyHash}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

func (b *backend) pkHashToAddress49(pkHash []byte) string {
	pkScript := slices.Concat([]byte{0, 20}, pkHash)
	data := slices.Concat([]byte{b.magicScriptHash},
		hashx.RipeMD160Sum(hashx.Sha256Sum(pkScript)))
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]
	return base58.Encode(slices.Concat(data, digest))
}

func (b *backend) pkHashToAddress84(pkHash []byte) string {
	return bech32.Encode(b.magicBech32HRP, []byte{0}, pkHash)
}
