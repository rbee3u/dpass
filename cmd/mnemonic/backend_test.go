package mnemonic

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip39"
	"github.com/rbee3u/dpass/pkg/testx"
)

func TestBackend(t *testing.T) {
	tests := []struct {
		name      string
		wordCount int
	}{
		{
			name:      "minimum",
			wordCount: bip39.MinWordCount,
		},
		{
			name:      "maximum",
			wordCount: bip39.MaxWordCount,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{wordCount: tt.wordCount}
			bWriter := testx.NewWriter(nil)
			b.writer = bWriter
			require.NoError(t, b.runE(nil, nil))
			require.Len(t, strings.Fields(bWriter.String()), tt.wordCount)
		})
	}
}

func TestBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		wordCount  int
		writer     *testx.Writer
		requireErr func(*testing.T, error)
	}{
		{
			name:      "invalid word count step",
			wordCount: bip39.MinWordCount + 1,
			writer:    testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to generate mnemonic")
				var target bip39.InvalidWordCountError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip39.MinWordCount+1, target.WordCount)
			},
		},
		{
			name:      "word count too small",
			wordCount: bip39.MinWordCount - bip39.WordCountStep,
			writer:    testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to generate mnemonic")
				var target bip39.InvalidWordCountError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip39.MinWordCount-bip39.WordCountStep, target.WordCount)
			},
		},
		{
			name:      "word count too large",
			wordCount: bip39.MaxWordCount + bip39.WordCountStep,
			writer:    testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to generate mnemonic")
				var target bip39.InvalidWordCountError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip39.MaxWordCount+bip39.WordCountStep, target.WordCount)
			},
		},
		{
			name:      "writer write failure",
			wordCount: bip39.MaxWordCount,
			writer:    testx.NewWriter(testx.ErrWriteFailure),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to write mnemonic")
				require.ErrorIs(t, err, testx.ErrWriteFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{wordCount: tt.wordCount}
			b.writer = tt.writer
			tt.requireErr(t, b.runE(nil, nil))
		})
	}
}
