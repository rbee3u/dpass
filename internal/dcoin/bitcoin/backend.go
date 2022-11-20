package bitcoin

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/rbee3u/dpass/third_party/github.com/decred/dcrd/dcrec/secp256k1"
	"github.com/rbee3u/dpass/third_party/github.com/mr-tron/base58"
	"github.com/rbee3u/dpass/third_party/github.com/tyler-smith/go-bip32"
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

func Register(cmd *cobra.Command) *cobra.Command {
	b := backendDefault()
	cmd.RunE = b.runE

	cmd.Flags().Uint32Var(&b.purpose, "purpose", purposeDefault, fmt.Sprintf(
		"purpose must be %v, %v or %v", purpose44, purpose49, purpose84))
	cmd.Flags().StringVar(&b.network, "network", networkDefault, fmt.Sprintf(
		"network must be %q, %q, %q or %q", networkMainNet, networkRegressionNet, networkTestNet3, networkSimNet))
	cmd.Flags().Uint32Var(&b.index, "index", indexDefault, fmt.Sprintf(
		"index is the number of address (default %v)", indexDefault))
	cmd.Flags().BoolVar(&b.secret, "secret", secretDefault, fmt.Sprintf(
		"show secret instead of address (default %t)", secretDefault))
	cmd.Flags().BoolVar(&b.decompress, "decompress", decompressDefault, fmt.Sprintf(
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

func (b *backend) skToWIF(sk *secp256k1.PrivateKey) string {
	data := append([]byte{b.magicPrivateKey}, sk.Serialize()...)
	if !b.decompress {
		data = append(data, 1)
	}

	return base58.Encode(append(data, dcoin.Sha256Sum(dcoin.Sha256Sum(data))[:4]...))
}

func (b *backend) pkToAddress(pk *secp256k1.PublicKey) string {
	var data []byte
	if !b.decompress {
		data = pk.SerializeCompressed()
	} else {
		data = pk.SerializeUncompressed()
	}

	return b.convert(dcoin.RipeMD160Sum(dcoin.Sha256Sum(data)))
}

func (b *backend) pkHashToAddress44(pkHash []byte) string {
	data := make([]byte, 0, 25)
	data = append(data, b.magicPubKeyHash)
	data = append(data, pkHash...)
	data = append(data, dcoin.Sha256Sum(dcoin.Sha256Sum(data))[:4]...)

	return base58.Encode(data)
}

func (b *backend) pkHashToAddress49(pkHash []byte) string {
	data := make([]byte, 0, 25)
	data = append(data, b.magicScriptHash)
	data = append(data, dcoin.RipeMD160Sum(dcoin.Sha256Sum(append([]byte{0, 20}, pkHash...)))...)
	data = append(data, dcoin.Sha256Sum(dcoin.Sha256Sum(data))[:4]...)

	return base58.Encode(data)
}

func (b *backend) pkHashToAddress84(pkHash []byte) string {
	const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

	hrp := strings.ToLower(b.magicBech32HRP)
	data := make([]byte, 0, len(hrp)+40)
	data = append(data, hrp...)
	data = append(data, '1', charset[0])

	polymod := uint32(1)
	iterate := func(v uint32) {
		polymod, v = ((polymod&0x1ffffff)<<5)^v, polymod
		polymod ^= (1 & (v >> 25)) * 0x3b6a57b2
		polymod ^= (1 & (v >> 26)) * 0x26508e6d
		polymod ^= (1 & (v >> 27)) * 0x1ea119fa
		polymod ^= (1 & (v >> 28)) * 0x3d4233dd
		polymod ^= (1 & (v >> 29)) * 0x2a1462b3
	}

	for i := 0; i < len(hrp); i++ {
		iterate(uint32(hrp[i] >> 5))
	}

	iterate(0)

	for i := 0; i < len(hrp); i++ {
		iterate(uint32(hrp[i] & 31))
	}

	for iterate(0); len(pkHash) != 0; pkHash = pkHash[5:] {
		for _, v := range []byte{
			pkHash[0] >> 3,
			((pkHash[0] << 2) | (pkHash[1] >> 6)) & 31,
			(pkHash[1] >> 1) & 31,
			((pkHash[1] << 4) | (pkHash[2] >> 4)) & 31,
			((pkHash[2] << 1) | (pkHash[3] >> 7)) & 31,
			(pkHash[3] >> 2) & 31,
			((pkHash[3] << 3) | (pkHash[4] >> 5)) & 31,
			pkHash[4] & 31,
		} {
			data = append(data, charset[v])
			iterate(uint32(v))
		}
	}

	for i := 0; i < 6; i++ {
		iterate(0)
	}

	return string(append(data,
		charset[(polymod>>25)&31], charset[(polymod>>20)&31], charset[(polymod>>15)&31],
		charset[(polymod>>10)&31], charset[(polymod>>5)&31], charset[(polymod^1)&31],
	))
}
