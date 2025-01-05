package main

import (
	"fmt"
	"os"

	"github.com/rbee3u/dpass/internal/dcoin/bitcoin"
	"github.com/rbee3u/dpass/internal/dcoin/dogecoin"
	"github.com/rbee3u/dpass/internal/dcoin/ethereum"
	"github.com/rbee3u/dpass/internal/dcoin/mnemonic"
	"github.com/rbee3u/dpass/internal/dcoin/solana"
	"github.com/rbee3u/dpass/internal/dcoin/sui"
	"github.com/rbee3u/dpass/internal/dcoin/tron"
	"github.com/spf13/cobra"
)

func main() {
	if err := newCmd().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dcoin", Args: cobra.NoArgs}
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.AddCommand(
		mnemonic.NewCmd(),
		bitcoin.NewCmd(),
		ethereum.NewCmd(),
		tron.NewCmd(),
		solana.NewCmd(),
		dogecoin.NewCmd(),
		sui.NewCmd(),
	)
	return cmd
}
