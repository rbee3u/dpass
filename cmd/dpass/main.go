package main

import (
	"fmt"
	"os"

	"github.com/rbee3u/dpass/internal/dpass/aes256"
	"github.com/rbee3u/dpass/internal/dpass/qrcode"
	"github.com/rbee3u/dpass/internal/dpass/shamir"
	"github.com/spf13/cobra"
)

func main() {
	if err := newCmd().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dpass", Args: cobra.NoArgs}
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	cmd.AddCommand(
		aes256.NewCmdEncrypt(),
		aes256.NewCmdDecrypt(),
		shamir.NewCmdSplit(),
		shamir.NewCmdCombine(),
		qrcode.NewCmd(),
	)

	return cmd
}
