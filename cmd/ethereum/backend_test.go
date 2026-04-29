package ethereum

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	getAddressAndSecret := func(t *testing.T, b *backend) (string, string) {
		t.Helper()
		address, err := b.getResult(mnemonic)
		require.NoError(t, err)
		secretBackend := *b
		secretBackend.secret = true
		private, err := secretBackend.getResult(mnemonic)
		require.NoError(t, err)
		return address, private
	}
	defaultAddress, defaultPrivate := getAddressAndSecret(t, backendDefault())
	tests := []struct {
		name           string
		account        uint32
		change         uint32
		index          uint32
		address        string
		private        string
		compareDefault bool
	}{
		{
			name:    "index0",
			index:   0,
			address: "0xF2E68B8894e098AB6b5936906AB5ea73De03712E",
			private: "17348e94f527e08782ca41f4fc9cf702f143e397630ba8b6dc11d85a1e1dfaad",
		},
		{
			name:    "index9",
			index:   9,
			address: "0xcFaCBb2323A0529c90E4a25234a2Aa0a21328AfF",
			private: "0ab1781468d0da1f9021d7be5e9c6e78618f9709d4c043f56f7af0a96418bc39",
		},
		{
			name:           "account1 changes output",
			account:        1,
			compareDefault: true,
		},
		{
			name:           "change1 changes output",
			change:         1,
			compareDefault: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			b.account = tt.account
			b.change = tt.change
			b.index = tt.index
			address, private := getAddressAndSecret(t, b)
			if tt.compareDefault {
				require.NotEqual(t, defaultAddress, address)
				require.NotEqual(t, defaultPrivate, private)
				return
			}
			require.Equal(t, tt.address, address)
			require.Equal(t, tt.private, private)
		})
	}
}

func TestBackendErrors(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		name       string
		setup      func(*backend)
		requireErr func(*testing.T, error)
	}{
		{
			name: "invalid account",
			setup: func(b *backend) {
				b.account = bip3x.FirstHardenedChild
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidAccountError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.FirstHardenedChild, target.Got)
			},
		},
		{
			name: "invalid change",
			setup: func(b *backend) {
				b.change = bip3x.FirstHardenedChild
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidChangeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.FirstHardenedChild, target.Got)
			},
		},
		{
			name: "invalid index",
			setup: func(b *backend) {
				b.index = bip3x.FirstHardenedChild
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidIndexError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.FirstHardenedChild, target.Got)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			tt.setup(b)
			result, err := b.getResult(mnemonic)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Empty(t, result)
		})
	}
}
