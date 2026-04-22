package qrcode

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"rsc.io/qr"
)

func TestBackend(t *testing.T) {
	tests := []struct {
		name     string
		text     string
		level    string
		levelInt qr.Level
		quiet    int
		swap     bool
		prefix   string
	}{
		{
			name:     "levelL quiet4",
			text:     "hello world",
			level:    levelL,
			levelInt: qr.L,
			quiet:    quietDefault,
			swap:     false,
			prefix:   "\u001B[47m  ",
		},
		{
			name:     "levelH quiet5 swap",
			text:     "hello world",
			level:    levelH,
			levelInt: qr.H,
			quiet:    quietDefault + 1,
			swap:     true,
			prefix:   "\u001B[40m  ",
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
			require.Equal(t, tt.levelInt, b.levelInt)

			code, err := qr.Encode(tt.text, tt.levelInt)
			require.NoError(t, err)

			rendered := string(result)
			lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
			expectedSide := code.Size + tt.quiet*2
			expectedLineLen := expectedSide*len("\u001B[47m  ") + len("\u001B[0m")

			require.Len(t, lines, expectedSide)
			require.True(t, strings.HasSuffix(rendered, "\u001B[0m\n"))
			require.True(t, strings.HasPrefix(lines[0], tt.prefix))
			require.Contains(t, rendered, "\u001B[40m  ")
			require.Contains(t, rendered, "\u001B[47m  ")

			for _, line := range lines {
				require.Len(t, line, expectedLineLen)
				require.True(t, strings.HasSuffix(line, "\u001B[0m"))
			}
		})
	}
}

func TestBackendMaxInputBytes(t *testing.T) {
	b := backendDefault()

	result, err := b.getResult(strings.Repeat("a", maxInputBytes))
	require.NoError(t, err)
	require.NotEmpty(t, result)
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
			require.Empty(t, result)
		})
	}
}
