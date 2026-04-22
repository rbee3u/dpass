// Package qrcode provides a CLI command for rendering stdin as terminal QR codes.
package qrcode

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"rsc.io/qr"
)

// QR rendering defaults and accepted flag bounds.
const (
	// levelDefault selects the lowest QR error-correction level by default.
	levelDefault = levelL
	// levelL selects QR error-correction level L.
	levelL = "L"
	// levelM selects QR error-correction level M.
	levelM = "M"
	// levelQ selects QR error-correction level Q.
	levelQ = "Q"
	// levelH selects QR error-correction level H.
	levelH = "H"

	// quietDefault sets the default quiet-zone width in modules.
	quietDefault = 4
	// quietMin is the smallest accepted quiet-zone width.
	quietMin = 4
	// quietMax is the largest accepted quiet-zone width.
	quietMax = 9
	// maxInputBytes is the largest accepted stdin payload size in bytes.
	maxInputBytes = 1000

	// swapDefault keeps standard black/white output by default.
	swapDefault = false
)

// backend holds error-correction level, quiet zone width, and optional color inversion.
type backend struct {
	// level keeps the user-provided error-correction level string for validation.
	level string
	// levelInt is the parsed qr.Level used by the encoder after validation.
	levelInt qr.Level
	// quiet is the margin width in modules around the symbol.
	quiet int
	// swap inverts black/white when mapping modules to ANSI colors.
	swap bool
}

// backendDefault matches common terminal QR settings (level L, quiet 4).
func backendDefault() *backend {
	return &backend{
		level: levelDefault,
		quiet: quietDefault,
		swap:  swapDefault,
	}
}

// NewCmd encodes stdin as a QR symbol and writes terminal graphics to stdout.
func NewCmd() *cobra.Command {
	backend := backendDefault()
	cmd := &cobra.Command{
		Use:   "qrcode",
		Short: "Render stdin as a terminal QR code",
		Example: "  printf 'https://example.com' | dpass qrcode\n" +
			"  printf 'hello' | dpass qrcode --level H --swap",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}
	cmd.Flags().StringVarP(&backend.level, "level", "l", levelDefault, fmt.Sprintf(
		"QR error correction level: one of %s/%s/%s/%s", levelL, levelM, levelQ, levelH))
	cmd.Flags().IntVarP(&backend.quiet, "quiet", "q", quietDefault, fmt.Sprintf(
		"quiet zone size in modules within [%d, %d]", quietMin, quietMax))
	cmd.Flags().BoolVarP(&backend.swap, "swap", "s", swapDefault,
		"invert terminal colors")

	return cmd
}

// runE encodes stdin as a QR bitmap rendered with ANSI background colors.
func (b *backend) runE(_ *cobra.Command, _ []string) error {
	text, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read text: %w", err)
	}

	textString := string(text)

	result, err := b.getResult(textString)
	if err != nil {
		return err
	}

	if _, err := os.Stdout.Write(result); err != nil {
		return fmt.Errorf("failed to write result: %w", err)
	}

	return nil
}

// getResult validates flags, encodes text as QR, and renders ANSI background-color cells.
func (b *backend) getResult(text string) ([]byte, error) {
	if err := b.checkArguments(text); err != nil {
		return nil, err
	}

	code, err := qr.Encode(text, b.levelInt)
	if err != nil {
		return nil, fmt.Errorf("failed to encode text: %w", err)
	}

	var result []byte

	for y := range b.quiet + code.Size + b.quiet {
		for x := range b.quiet + code.Size + b.quiet {
			if code.Black(x-b.quiet, y-b.quiet) != b.swap {
				result = append(result, "\u001B[40m  "...)
			} else {
				result = append(result, "\u001B[47m  "...)
			}
		}

		result = append(result, "\u001B[0m\n"...)
	}

	return result, nil
}

// checkArguments maps string flags to rsc.io/qr levels and validates quiet zone and input size.
func (b *backend) checkArguments(text string) error {
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
		return invalidLevelError{
			Got:     b.level,
			Allowed: []string{levelL, levelM, levelQ, levelH},
		}
	}

	if b.quiet < quietMin || quietMax < b.quiet {
		return invalidQuietError{Got: b.quiet, Min: quietMin, Max: quietMax}
	}

	if len(text) > maxInputBytes {
		return inputTooLongError{Got: len(text), Max: maxInputBytes}
	}

	return nil
}
