package main

import (
	"fmt"
	"os"

	"github.com/rbee3u/dpass/internal/dcoin/bitcoin"
	"github.com/rbee3u/dpass/internal/dcoin/ethereum"
	"github.com/rbee3u/dpass/internal/dcoin/mnemonic"
	"github.com/spf13/cobra"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dcoin", Args: cobra.NoArgs}
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	cmd.AddCommand(mnemonicCmd(), bitcoinCmd(), ethereumCmd())

	return cmd
}

func mnemonicCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "mnemonic", Args: cobra.NoArgs}

	mnemonic.RegisterBackend(cmd)

	return cmd
}

func bitcoinCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "bitcoin", Args: cobra.NoArgs}

	bitcoin.RegisterBackend(cmd)

	return cmd
}

func ethereumCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ethereum", Args: cobra.NoArgs}

	ethereum.RegisterBackend(cmd)

	return cmd
}
