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

	cmd.AddCommand(encryptCmd(), decryptCmd(), splitCmd(), combineCmd(), qrcodeCmd())

	return cmd
}

func encryptCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "encrypt", Args: cobra.NoArgs}

	aes256.RegisterEncryptBackend(cmd)

	return cmd
}

func decryptCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "decrypt", Args: cobra.NoArgs}

	aes256.RegisterDecryptBackend(cmd)

	return cmd
}

func splitCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "split", Args: cobra.NoArgs}

	shamir.RegisterSplitBackend(cmd)

	return cmd
}

func combineCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "combine", Args: cobra.NoArgs}

	shamir.RegisterCombineBackend(cmd)

	return cmd
}

func qrcodeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "qrcode", Args: cobra.NoArgs}

	qrcode.RegisterBackend(cmd)

	return cmd
}
