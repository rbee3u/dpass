package qrcode

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"rsc.io/qr"

	"github.com/rbee3u/dpass/pkg/testx"
)

func TestBackend(t *testing.T) {
	tests := []struct {
		name  string
		level string
		quiet int
		swap  bool
		text  []byte
	}{
		{
			name:  "level L",
			level: levelL,
			quiet: quietMin,
			text:  []byte("hello"),
		},
		{
			name:  "level Q",
			level: levelQ,
			quiet: quietMin,
			text:  []byte("hello"),
		},
		{
			name:  "level H",
			level: levelH,
			quiet: quietMin,
			text:  []byte("hello"),
		},
		{
			name:  "quiet min",
			level: levelM,
			quiet: quietMin,
			text:  []byte("hello"),
		},
		{
			name:  "quiet max",
			level: levelM,
			quiet: quietMax,
			text:  []byte("hello"),
		},
		{
			name:  "swap",
			level: levelM,
			quiet: quietMin,
			swap:  true,
			text:  []byte("hello"),
		},
		{
			name:  "max input bytes",
			level: levelM,
			quiet: quietMin,
			text:  bytes.Repeat([]byte("a"), maxInputBytes),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{level: tt.level, quiet: tt.quiet, swap: tt.swap}
			b.reader = testx.NewReader(tt.text, nil)
			bWriter := testx.NewWriter(nil)
			b.writer = bWriter
			require.NoError(t, b.runE(nil, nil))
			level, err := b.checkFlags()
			require.NoError(t, err)
			code, err := qr.Encode(string(tt.text), level)
			require.NoError(t, err)
			var result bytes.Buffer
			for y := range tt.quiet + code.Size + tt.quiet {
				for x := range tt.quiet + code.Size + tt.quiet {
					if code.Black(x-tt.quiet, y-tt.quiet) != tt.swap {
						result.WriteString("\u001B[40m  ")
					} else {
						result.WriteString("\u001B[47m  ")
					}
				}
				result.WriteString("\u001B[0m\n")
			}
			require.Equal(t, result.Bytes(), bWriter.Bytes())
		})
	}
}

func TestBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		level      string
		quiet      int
		reader     *testx.Reader
		writer     *testx.Writer
		requireErr func(*testing.T, error)
	}{
		{
			name:   "invalid level",
			level:  "X",
			quiet:  quietMin,
			reader: testx.NewReader([]byte("hello"), nil),
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target invalidLevelError
				require.ErrorAs(t, err, &target)
				require.Equal(t, "X", target.level)
			},
		},
		{
			name:   "quiet below range",
			level:  levelM,
			quiet:  quietMin - 1,
			reader: testx.NewReader([]byte("hello"), nil),
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target invalidQuietError
				require.ErrorAs(t, err, &target)
				require.Equal(t, quietMin-1, target.quiet)
			},
		},
		{
			name:   "quiet above range",
			level:  levelM,
			quiet:  quietMax + 1,
			reader: testx.NewReader([]byte("hello"), nil),
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target invalidQuietError
				require.ErrorAs(t, err, &target)
				require.Equal(t, quietMax+1, target.quiet)
			},
		},
		{
			name:   "reader read failure",
			level:  levelM,
			quiet:  quietMin,
			reader: testx.NewReader(nil, testx.ErrReadFailure),
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read text")
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
		{
			name:   "writer write failure",
			level:  levelM,
			quiet:  quietMin,
			reader: testx.NewReader([]byte("hello"), nil),
			writer: testx.NewWriter(testx.ErrWriteFailure),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to write result")
				require.ErrorIs(t, err, testx.ErrWriteFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{level: tt.level, quiet: tt.quiet}
			b.reader, b.writer = tt.reader, tt.writer
			tt.requireErr(t, b.runE(nil, nil))
		})
	}
}
