package bitcoin

import (
	"errors"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/rbee3u/dpass/internal/dcoin"
	"github.com/spf13/cobra"
	"github.com/tyler-smith/go-bip32"
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
	purpose    uint32
	convert    func([]byte) (string, error)
	network    string
	params     *chaincfg.Params
	coin       uint32
	account    uint32
	change     uint32
	index      uint32
	secret     bool
	decompress bool
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
		b.params, b.coin = &chaincfg.MainNetParams, coinMain
	case networkRegressionNet:
		b.params, b.coin = &chaincfg.RegressionNetParams, coinTest
	case networkTestNet3:
		b.params, b.coin = &chaincfg.TestNet3Params, coinTest
	case networkSimNet:
		b.params, b.coin = &chaincfg.SimNetParams, coinTest
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

	privateKey, _ := btcec.PrivKeyFromBytes(key.Key)

	wif, err := btcutil.NewWIF(privateKey, b.params, !b.decompress)
	if err != nil {
		return "", fmt.Errorf("failed to new wif from private key: %w", err)
	}

	if b.secret {
		return wif.String(), nil
	}

	return b.convert(btcutil.Hash160(wif.SerializePubKey()))
}

func (b *backend) pkHashToAddress44(pkHash []byte) (string, error) {
	p2pkhAddress, err := btcutil.NewAddressPubKeyHash(pkHash, b.params)
	if err != nil {
		return "", fmt.Errorf("failed to new P2PKH address: %w", err)
	}

	return p2pkhAddress.EncodeAddress(), nil
}

func (b *backend) pkHashToAddress49(pkHash []byte) (string, error) {
	p2wpkhAddress, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, b.params)
	if err != nil {
		return "", fmt.Errorf("failed to new P2WPKH address: %w", err)
	}

	script, err := txscript.PayToAddrScript(p2wpkhAddress)
	if err != nil {
		return "", fmt.Errorf("failed to new script: %w", err)
	}

	p2shAddress, err := btcutil.NewAddressScriptHash(script, b.params)
	if err != nil {
		return "", fmt.Errorf("failed to new P2SH address: %w", err)
	}

	return p2shAddress.EncodeAddress(), nil
}

func (b *backend) pkHashToAddress84(pkHash []byte) (string, error) {
	p2wpkhAddress, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, b.params)
	if err != nil {
		return "", fmt.Errorf("failed to new P2WPKH address: %w", err)
	}

	return p2wpkhAddress.EncodeAddress(), nil
}
