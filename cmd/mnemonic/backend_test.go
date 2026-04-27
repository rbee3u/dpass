package mnemonic

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	tests := []struct {
		name      string
		size      int
		wordCount int
	}{
		{
			name:      "default size",
			size:      backendDefault().size,
			wordCount: 24,
		},
		{
			name:      "minimum size",
			size:      bip3x.EntropyBitsMin,
			wordCount: 12,
		},
		{
			name:      "middle size",
			size:      160,
			wordCount: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			b.size = tt.size

			result, err := b.getResult()
			require.NoError(t, err)
			require.Len(t, strings.Fields(result), tt.wordCount)

			_, err = bip3x.MnemonicToSeed(result, "")
			require.NoError(t, err)
		})
	}
}

func TestBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(*backend)
		requireErr func(*testing.T, error)
	}{
		{
			name: "below minimum",
			setup: func(b *backend) {
				b.size = bip3x.EntropyBitsMin - bip3x.EntropyBitsStep
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to generate random entropy")
				var target bip3x.InvalidEntropyBitsError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.EntropyBitsMin-bip3x.EntropyBitsStep, target.Bits)
			},
		},
		{
			name: "above maximum",
			setup: func(b *backend) {
				b.size = bip3x.EntropyBitsMax + bip3x.EntropyBitsStep
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to generate random entropy")
				var target bip3x.InvalidEntropyBitsError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.EntropyBitsMax+bip3x.EntropyBitsStep, target.Bits)
			},
		},
		{
			name: "invalid step",
			setup: func(b *backend) {
				b.size = bip3x.EntropyBitsMin + 1
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to generate random entropy")
				var target bip3x.InvalidEntropyBitsError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.EntropyBitsMin+1, target.Bits)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			tt.setup(b)

			result, err := b.getResult()
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Empty(t, result)
		})
	}
}
