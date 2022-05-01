package main

import (
	"fmt"
	"os"

	"github.com/rbee3u/dpass/internal/dcoin/btc"
	"github.com/rbee3u/dpass/internal/dcoin/eth"
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
	cmd := &cobra.Command{
		Use:           "dcoin",
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
	}

	cmd.AddCommand(
		mnemonicCmd(),
		btcCmd(),
		ethCmd(),
	)

	return cmd
}

func mnemonicCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "mnemonic", Args: cobra.NoArgs}

	mnemonic.RegisterBackend(cmd)

	return cmd
}

func btcCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "btc", Args: cobra.NoArgs}

	btc.RegisterBackend(cmd)

	return cmd
}

func ethCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "eth", Args: cobra.NoArgs}

	eth.RegisterBackend(cmd)

	return cmd
}
