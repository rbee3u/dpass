// Package bitcoin provides a CLI command for deriving Bitcoin addresses and WIF keys from mnemonics.
package bitcoin

import (
	"fmt"
	"math/big"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/bech32"
	"github.com/rbee3u/dpass/pkg/bip3x"
	"github.com/rbee3u/dpass/pkg/hashx"
	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/secp256k1"
)

// Purpose, network, and derivation defaults for the Bitcoin command.
const (
	// purposeDefault selects native SegWit derivation by default.
	purposeDefault = purpose84
	// purpose44 selects legacy P2PKH derivation.
	purpose44 = 44
	// purpose49 selects nested SegWit P2WPKH-in-P2SH derivation.
	purpose49 = 49
	// purpose84 selects native SegWit P2WPKH derivation.
	purpose84 = 84

	// networkDefault selects Bitcoin mainnet by default.
	networkDefault = networkMainNet
	// networkMainNet selects Bitcoin mainnet address and WIF prefixes.
	networkMainNet = "mainnet"
	// networkRegressionNet selects Bitcoin regtest address and WIF prefixes.
	networkRegressionNet = "regtest"
	// networkTestNet3 selects Bitcoin testnet3 address and WIF prefixes.
	networkTestNet3 = "testnet3"
	// networkSimNet selects btcd-style simnet address and WIF prefixes.
	networkSimNet = "simnet"

	// coinMain is the BIP44 coin type for Bitcoin mainnet.
	coinMain = 0
	// coinTest is the BIP44 coin type shared by the configured Bitcoin test networks.
	coinTest = 1

	// accountDefault selects the first account.
	accountDefault = 0
	// changeDefault selects the external address chain.
	changeDefault = 0
	// indexDefault selects the first address index.
	indexDefault = 0
	// secretDefault prints an address instead of a WIF by default.
	secretDefault = false
	// decompressDefault keeps compressed-key encoding by default.
	decompressDefault = false
)

// backend holds CLI flags that affect derivation and output encoding.
type backend struct {
	// purpose selects BIP44 (44), nested SegWit (49), or native SegWit (84).
	purpose uint32
	// network selects chain parameters (mainnet, testnets, etc.).
	network string
	// account is the hardened account segment in the derivation path.
	account uint32
	// change is the first unhardened trailing path component.
	change uint32
	// index is the second unhardened trailing path component.
	index uint32
	// secret requests WIF output instead of a payment address.
	secret bool
	// decompress uses an uncompressed pubkey when building the address hash or WIF.
	decompress bool
}

// backendDefault returns CLI defaults matching Bitcoin mainnet and native SegWit.
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

// NewCmd reads a mnemonic from stdin and prints a derived address or WIF.
func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{
		Use:   "bitcoin",
		Short: "Derive a Bitcoin address or private key from a mnemonic",
		Example: "  dpass mnemonic | dpass bitcoin\n" +
			"  dpass mnemonic | dpass bitcoin --network testnet3 --purpose 49 --account 1 --index 2\n" +
			"  dpass mnemonic | dpass bitcoin --secret",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}
	cmd.Flags().Uint32Var(&backend.purpose, "purpose", purposeDefault, fmt.Sprintf(
		"BIP purpose: one of %d (legacy P2PKH) / %d (nested SegWit) / %d (native SegWit)",
		purpose44, purpose49, purpose84))
	cmd.Flags().StringVar(&backend.network, "network", networkDefault, fmt.Sprintf(
		"Bitcoin network: one of %s/%s/%s/%s",
		networkMainNet, networkRegressionNet, networkTestNet3, networkSimNet))
	cmd.Flags().Uint32Var(&backend.account, "account", accountDefault, "BIP44 account index")
	cmd.Flags().Uint32Var(&backend.change, "change", changeDefault, "BIP44 change segment")
	cmd.Flags().Uint32Var(&backend.index, "index", indexDefault, "BIP44 address index")
	cmd.Flags().BoolVar(&backend.secret, "secret", secretDefault,
		"output private key (WIF) instead of address")
	cmd.Flags().BoolVar(&backend.decompress, "decompress", decompressDefault,
		"use an uncompressed public key (legacy purpose 44 only)")

	return cmd
}

type networkConfig struct {
	coin            uint32
	magicPrivateKey byte
	magicPubKeyHash byte
	magicScriptHash byte
	magicBech32HRP  string
}

// checkArguments validates CLI flags without mutating backend state.
func (b *backend) checkArguments() error {
	if _, err := b.resolvePurpose(); err != nil {
		return err
	}

	if _, err := b.resolveNetwork(); err != nil {
		return err
	}

	if b.account >= bip3x.FirstHardenedChild {
		return invalidAccountError{Got: b.account}
	}

	if b.change >= bip3x.FirstHardenedChild {
		return invalidChangeError{Got: b.change}
	}

	if b.index >= bip3x.FirstHardenedChild {
		return invalidIndexError{Got: b.index}
	}

	if b.decompress && b.purpose != purpose44 {
		return invalidDecompressPurposeError{Purpose: b.purpose}
	}

	return nil
}

// resolvePurpose validates the selected purpose and returns the matching address encoder.
func (b *backend) resolvePurpose() (func([]byte, networkConfig) (string, error), error) {
	switch b.purpose {
	case purpose44:
		return pkHashToAddress44, nil
	case purpose49:
		return pkHashToAddress49, nil
	case purpose84:
		return pkHashToAddress84, nil
	default:
		return nil, invalidPurposeError{
			Got:     b.purpose,
			Allowed: []uint32{purpose44, purpose49, purpose84},
		}
	}
}

// resolveNetwork validates the selected network and returns its encoding parameters.
func (b *backend) resolveNetwork() (networkConfig, error) {
	switch b.network {
	case networkMainNet:
		return networkConfig{
			coin:            coinMain,
			magicPrivateKey: 0x80,
			magicPubKeyHash: 0x00,
			magicScriptHash: 0x05,
			magicBech32HRP:  "bc",
		}, nil
	case networkRegressionNet:
		return networkConfig{
			coin:            coinTest,
			magicPrivateKey: 0xef,
			magicPubKeyHash: 0x6f,
			magicScriptHash: 0xc4,
			magicBech32HRP:  "bcrt",
		}, nil
	case networkTestNet3:
		return networkConfig{
			coin:            coinTest,
			magicPrivateKey: 0xef,
			magicPubKeyHash: 0x6f,
			magicScriptHash: 0xc4,
			magicBech32HRP:  "tb",
		}, nil
	case networkSimNet:
		return networkConfig{
			coin:            coinTest,
			magicPrivateKey: 0x64,
			magicPubKeyHash: 0x3f,
			magicScriptHash: 0x7b,
			magicBech32HRP:  "sb",
		}, nil
	default:
		return networkConfig{}, invalidNetworkError{
			Got:     b.network,
			Allowed: []string{networkMainNet, networkRegressionNet, networkTestNet3, networkSimNet},
		}
	}
}

// runE reads a mnemonic from stdin and prints the derived address or WIF.
func (b *backend) runE(_ *cobra.Command, _ []string) error {
	mnemonic, err := helper.ReadMnemonic()
	if err != nil {
		return err
	}

	result, err := b.getResult(mnemonic)
	if err != nil {
		return err
	}

	if _, err := os.Stdout.WriteString(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}

	return nil
}

// getResult derives the secp256k1 key along the BIP32 path and formats output per flags.
func (b *backend) getResult(mnemonic string) (string, error) {
	if err := b.checkArguments(); err != nil {
		return "", err
	}

	convert, err := b.resolvePurpose()
	if err != nil {
		return "", err
	}

	network, err := b.resolveNetwork()
	if err != nil {
		return "", err
	}

	seed, err := bip3x.MnemonicToSeed(mnemonic, "")
	if err != nil {
		return "", fmt.Errorf("failed to convert mnemonic to seed: %w", err)
	}

	sk, err := bip3x.Secp256k1DeriveSk(seed, []uint32{
		b.purpose + bip3x.FirstHardenedChild,
		network.coin + bip3x.FirstHardenedChild,
		b.account + bip3x.FirstHardenedChild,
		b.change,
		b.index,
	})
	if err != nil {
		return "", fmt.Errorf("failed to derive private key: %w", err)
	}

	if b.secret {
		return b.skToWIF(sk, network), nil
	}

	x, y := secp256k1.S256().ScalarBaseMult(sk)

	return b.pkToAddress(x, y, network, convert)
}

// skToWIF encodes the secret with network prefix, optional compressed suffix, and Base58Check.
func (b *backend) skToWIF(sk []byte, network networkConfig) string {
	data := slices.Concat([]byte{network.magicPrivateKey}, sk)
	if !b.decompress {
		data = append(data, 1)
	}

	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]

	return base58.Encode(slices.Concat(data, digest))
}

// pkToAddress hashes the compressed or uncompressed pubkey and encodes the result per purpose.
func (b *backend) pkToAddress(
	x, y *big.Int,
	network networkConfig,
	convert func([]byte, networkConfig) (string, error),
) (string, error) {
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

	return convert(pkHash, network)
}

// pkHashToAddress44 builds a P2PKH Base58Check address (BIP44 legacy).
func pkHashToAddress44(pkHash []byte, network networkConfig) (string, error) {
	data := slices.Concat([]byte{network.magicPubKeyHash}, pkHash)
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]

	return base58.Encode(slices.Concat(data, digest)), nil
}

// pkHashToAddress49 wraps the pubkey hash in P2WPKH-in-P2SH and Base58Check-encodes it.
func pkHashToAddress49(pkHash []byte, network networkConfig) (string, error) {
	pkScript := slices.Concat([]byte{0, 20}, pkHash)
	data := slices.Concat([]byte{network.magicScriptHash},
		hashx.RipeMD160Sum(hashx.Sha256Sum(pkScript)))
	digest := hashx.Sha256Sum(hashx.Sha256Sum(data))[:4]

	return base58.Encode(slices.Concat(data, digest)), nil
}

// pkHashToAddress84 Bech32-encodes witness version 0 with the pubkey hash (BIP84).
func pkHashToAddress84(pkHash []byte, network networkConfig) (string, error) {
	address, err := bech32.EncodeChecked(network.magicBech32HRP, []byte{0}, pkHash)
	if err != nil {
		return "", fmt.Errorf("failed to encode bech32 address: %w", err)
	}

	return address, nil
}
