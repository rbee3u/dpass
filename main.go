// Package main wires the dpass CLI and its subcommands.
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/cmd/aes256"
	"github.com/rbee3u/dpass/cmd/bitcoin"
	"github.com/rbee3u/dpass/cmd/dogecoin"
	"github.com/rbee3u/dpass/cmd/ethereum"
	"github.com/rbee3u/dpass/cmd/mnemonic"
	"github.com/rbee3u/dpass/cmd/qrcode"
	"github.com/rbee3u/dpass/cmd/shamir"
	"github.com/rbee3u/dpass/cmd/solana"
	"github.com/rbee3u/dpass/cmd/sui"
	"github.com/rbee3u/dpass/cmd/tron"
)

// version is the CLI release string shown by --version.
const version = "v1.5.4"

// main builds and executes the root CLI; it prints errors to stderr and exits with status 1 on failure.
func main() {
	cmd := &cobra.Command{
		Use:   "dpass",
		Short: "CLI toolkit for secret sharing, encryption, mnemonics, and multi-chain key derivation",
		Long: "dpass is a CLI toolkit that protects secrets with Shamir splitting and AES-256-GCM\n" +
			"encryption, generates BIP-39 mnemonics, and derives addresses or private keys for\n" +
			"Bitcoin, Ethereum, Tron, Solana, Dogecoin, and Sui.",
		Example: "  printf 'correct horse battery staple' | dpass split\n" +
			"  cat shares.pem | dpass combine\n" +
			"  dpass mnemonic | dpass bitcoin",
		Args:          cobra.NoArgs,
		Version:       version,
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		aes256.NewCmdEncrypt(),
		aes256.NewCmdDecrypt(),
		shamir.NewCmdSplit(),
		shamir.NewCmdCombine(),
		qrcode.NewCmd(),
		mnemonic.NewCmd(),
		bitcoin.NewCmd(),
		ethereum.NewCmd(),
		tron.NewCmd(),
		solana.NewCmd(),
		dogecoin.NewCmd(),
		sui.NewCmd(),
	)

	if err := cmd.Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)

		os.Exit(1)
	}
}
