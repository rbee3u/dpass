package qrcode

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"rsc.io/qr"
)

func TestBackend(t *testing.T) {
	splitRenderedLines := func(rendered string) []string {
		return strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
	}
	expectedQRCodeCell := func(code *qr.Code, quiet int, swap bool, x int, y int) string {
		isBlack := false
		if quiet <= x && x < quiet+code.Size && quiet <= y && y < quiet+code.Size {
			isBlack = code.Black(x-quiet, y-quiet)
		}

		if isBlack != swap {
			return "\u001B[40m  "
		}

		return "\u001B[47m  "
	}
	verifyRenderedQRCode := func(t *testing.T, text string, wantLevel qr.Level, quiet int, swap bool, b *backend, result []byte) {
		t.Helper()
		code, err := qr.Encode(text, wantLevel)
		require.NoError(t, err)
		rendered := string(result)
		lines := splitRenderedLines(rendered)
		expectedSide := code.Size + quiet*2
		expectedLineLen := expectedSide*len("\u001B[47m  ") + len("\u001B[0m")
		require.Equal(t, wantLevel, b.levelInt)
		require.NotEmpty(t, result)
		require.Len(t, lines, expectedSide)
		require.True(t, strings.HasSuffix(rendered, "\u001B[0m\n"))
		require.True(t, strings.HasPrefix(lines[0], expectedQRCodeCell(code, quiet, swap, 0, 0)))
		require.Contains(t, rendered, "\u001B[40m  ")
		require.Contains(t, rendered, "\u001B[47m  ")
		for y, line := range lines {
			require.Len(t, line, expectedLineLen)
			require.True(t, strings.HasSuffix(line, "\u001B[0m"))
			line = strings.TrimSuffix(line, "\u001B[0m")
			for x := range expectedSide {
				cell := line[x*len("\u001B[47m  ") : (x+1)*len("\u001B[47m  ")]
				require.Equal(t, expectedQRCodeCell(code, quiet, swap, x, y), cell)
			}
		}
	}
	tests := []struct {
		name      string
		text      string
		level     string
		wantLevel qr.Level
		quiet     int
		swap      bool
	}{
		{
			name:      "levelL quiet4",
			text:      "hello world",
			level:     levelL,
			wantLevel: qr.L,
			quiet:     quietDefault,
			swap:      false,
		},
		{
			name:      "levelH quiet5 swap",
			text:      "hello world",
			level:     levelH,
			wantLevel: qr.H,
			quiet:     quietDefault + 1,
			swap:      true,
		},
		{
			name:      "max input bytes",
			text:      strings.Repeat("a", maxInputBytes),
			level:     levelL,
			wantLevel: qr.L,
			quiet:     quietDefault,
			swap:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			b.level = tt.level
			b.quiet = tt.quiet
			b.swap = tt.swap
			result, err := b.getResult(tt.text)
			require.NoError(t, err)
			verifyRenderedQRCode(t, tt.text, tt.wantLevel, tt.quiet, tt.swap, b, result)
		})
	}
}

func TestBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		text       string
		setup      func(*backend)
		requireErr func(*testing.T, error)
	}{
		{
			name: "invalid level",
			text: "hello world",
			setup: func(b *backend) {
				b.level = "X"
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidLevelError
				require.ErrorAs(t, err, &target)
				require.Equal(t, "X", target.Got)
				require.Equal(t, []string{levelL, levelM, levelQ, levelH}, target.Allowed)
			},
		},
		{
			name: "quiet below range",
			text: "hello world",
			setup: func(b *backend) {
				b.quiet = quietMin - 1
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidQuietError
				require.ErrorAs(t, err, &target)
				require.Equal(t, quietMin-1, target.Got)
				require.Equal(t, quietMin, target.Min)
				require.Equal(t, quietMax, target.Max)
			},
		},
		{
			name: "quiet above range",
			text: "hello world",
			setup: func(b *backend) {
				b.quiet = quietMax + 1
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidQuietError
				require.ErrorAs(t, err, &target)
				require.Equal(t, quietMax+1, target.Got)
			},
		},
		{
			name: "input too long",
			text: strings.Repeat("a", maxInputBytes+1),
			setup: func(*backend) {
			},
			requireErr: func(t *testing.T, err error) {
				var target inputTooLongError
				require.ErrorAs(t, err, &target)
				require.Equal(t, maxInputBytes+1, target.Got)
				require.Equal(t, maxInputBytes, target.Max)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			tt.setup(b)
			result, err := b.getResult(tt.text)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, result)
		})
	}
}
