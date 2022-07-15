package main

import (
	"fmt"
	"os"

	"github.com/rbee3u/dpass/internal/dcoin/bitcoin"
	"github.com/rbee3u/dpass/internal/dcoin/ethereum"
	"github.com/rbee3u/dpass/internal/dcoin/mnemonic"
	"github.com/rbee3u/dpass/internal/dcoin/solana"
	"github.com/rbee3u/dpass/internal/dcoin/tron"
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

	cmd.AddCommand(
		mnemonic.Register(&cobra.Command{Use: "mnemonic", Args: cobra.NoArgs}),
		bitcoin.Register(&cobra.Command{Use: "bitcoin", Args: cobra.NoArgs}),
		ethereum.Register(&cobra.Command{Use: "ethereum", Args: cobra.NoArgs}),
		tron.Register(&cobra.Command{Use: "tron", Args: cobra.NoArgs}),
		solana.Register(&cobra.Command{Use: "solana", Args: cobra.NoArgs}),
	)

	return cmd
}
