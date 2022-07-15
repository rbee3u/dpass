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
	if err := rootCmd().Execute(); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func rootCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dpass", Args: cobra.NoArgs}
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	cmd.AddCommand(
		aes256.RegisterEncrypt(&cobra.Command{Use: "encrypt", Args: cobra.NoArgs}),
		aes256.RegisterDecrypt(&cobra.Command{Use: "decrypt", Args: cobra.NoArgs}),
		shamir.RegisterSplit(&cobra.Command{Use: "split", Args: cobra.NoArgs}),
		shamir.RegisterCombine(&cobra.Command{Use: "combine", Args: cobra.NoArgs}),
		qrcode.Register(&cobra.Command{Use: "qrcode", Args: cobra.NoArgs}),
	)

	return cmd
}
