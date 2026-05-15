// Package qrcode provides a CLI command for rendering stdin as terminal QR codes.
package qrcode

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"rsc.io/qr"

	"github.com/rbee3u/dpass/pkg/helper"
)

const (
	levelL        = "L"
	levelM        = "M"
	levelQ        = "Q"
	levelH        = "H"
	quietMin      = 4
	quietMax      = 9
	maxInputBytes = 1000
)

type backend struct {
	level  string
	quiet  int
	swap   bool
	reader io.Reader
	writer io.Writer
}

// NewCmd returns the qrcode command. The command reads stdin and writes
// terminal QR graphics to stdout.
func NewCmd() *cobra.Command {
	b := &backend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "qrcode",
		Short: "Render stdin as a terminal QR code",
		Example: "  printf 'https://example.com' | dpass qrcode\n" +
			"  printf 'hello' | dpass qrcode --level H --swap",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().StringVarP(&b.level, "level", "l", levelM, fmt.Sprintf(
		"QR error correction level: one of %s/%s/%s/%s", levelL, levelM, levelQ, levelH,
	))
	cmd.Flags().IntVarP(&b.quiet, "quiet", "q", quietMin, fmt.Sprintf(
		"quiet zone size in modules within [%d, %d]", quietMin, quietMax,
	))
	cmd.Flags().BoolVarP(&b.swap, "swap", "s", false, "invert terminal colors")
	return cmd
}

func (b *backend) runE(_ *cobra.Command, _ []string) error {
	level, err := b.checkFlags()
	if err != nil {
		return err
	}
	text, err := helper.ReadAllLimited(b.reader, maxInputBytes)
	if err != nil {
		return fmt.Errorf("failed to read text: %w", err)
	}
	code, err := qr.Encode(string(text), level)
	if err != nil {
		return fmt.Errorf("failed to encode text: %w", err)
	}
	var result bytes.Buffer
	for y := range b.quiet + code.Size + b.quiet {
		for x := range b.quiet + code.Size + b.quiet {
			if code.Black(x-b.quiet, y-b.quiet) != b.swap {
				result.WriteString("\u001B[40m  ")
			} else {
				result.WriteString("\u001B[47m  ")
			}
		}
		result.WriteString("\u001B[0m\n")
	}
	if _, err := b.writer.Write(result.Bytes()); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}
	return nil
}

func (b *backend) checkFlags() (qr.Level, error) {
	var level qr.Level
	switch b.level {
	case levelL:
		level = qr.L
	case levelM:
		level = qr.M
	case levelH:
		level = qr.H
	case levelQ:
		level = qr.Q
	default:
		return 0, invalidLevelError{level: b.level}
	}
	if b.quiet < quietMin || b.quiet > quietMax {
		return 0, invalidQuietError{quiet: b.quiet}
	}
	return level, nil
}
