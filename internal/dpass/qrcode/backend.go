package qrcode

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"rsc.io/qr"
)

const (
	levelDefault = levelL
	levelL       = "L"
	levelM       = "M"
	levelQ       = "Q"
	levelH       = "H"

	quietDefault = 2
	quietMin     = 0
	quietMax     = 9

	swapDefault = false
)

var (
	errInvalidLevel = errors.New("invalid level")
	errInvalidQuiet = errors.New("invalid quiet")
)

type backend struct {
	level    string
	levelInt qr.Level
	quiet    int
	swap     bool
}

func backendDefault() *backend {
	return &backend{
		level: levelDefault,
		quiet: quietDefault,
		swap:  swapDefault,
	}
}

func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{Use: "qrcode", Args: cobra.NoArgs, RunE: backend.runE}
	cmd.Flags().StringVarP(&backend.level, "level", "l", levelDefault, fmt.Sprintf(
		"error correction level (%q | %q | %q | %q)", levelL, levelM, levelQ, levelH))
	cmd.Flags().IntVarP(&backend.quiet, "quiet", "q", quietDefault, fmt.Sprintf(
		"quiet zone border size, must be in range [%v, %v]", quietMin, quietMax))
	cmd.Flags().BoolVarP(&backend.swap, "swap", "s", swapDefault, fmt.Sprintf(
		"swap black and white pixels (default %t)", swapDefault))
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	if err := b.checkArguments(); err != nil {
		return fmt.Errorf("failed to check arguments: %w", err)
	}
	text, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read text: %w", err)
	}
	code, err := qr.Encode(string(text), b.levelInt)
	if err != nil {
		return fmt.Errorf("failed to encode text: %w", err)
	}
	if _, err := os.Stdout.Write(b.transformCode(code)); err != nil {
		return fmt.Errorf("failed to write transformed code: %w", err)
	}
	return nil
}

func (b *backend) checkArguments() error {
	switch b.level {
	case levelL:
		b.levelInt = qr.L
	case levelM:
		b.levelInt = qr.M
	case levelH:
		b.levelInt = qr.H
	case levelQ:
		b.levelInt = qr.Q
	default:
		return errInvalidLevel
	}
	if b.quiet < quietMin || quietMax < b.quiet {
		return errInvalidQuiet
	}
	return nil
}

func (b *backend) transformCode(code *qr.Code) []byte {
	var data []byte
	for y := range b.quiet + code.Size + b.quiet {
		for x := range b.quiet + code.Size + b.quiet {
			if code.Black(x-b.quiet, y-b.quiet) != b.swap {
				data = append(data, "\u001B[40m  "...)
			} else {
				data = append(data, "\u001B[47m  "...)
			}
		}
		data = append(data, "\u001B[0m\n"...)
	}
	return data
}
