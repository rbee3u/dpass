package ethereum

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		name    string
		index   uint32
		address string
		private string
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := backendDefault()
			pb.index = tt.index
			address, err := pb.getResult(mnemonic)
			require.NoError(t, err)
			require.Equal(t, tt.address, address)
			sb := backendDefault()
			sb.index = tt.index
			sb.secret = true
			private, err := sb.getResult(mnemonic)
			require.NoError(t, err)
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
			name: "invalid purpose",
			setup: func(b *backend) {
				b.purpose = bip3x.FirstHardenedChild
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidPurposeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.FirstHardenedChild, target.Got)
			},
		},
		{
			name: "invalid coin",
			setup: func(b *backend) {
				b.coin = bip3x.FirstHardenedChild
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidCoinError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip3x.FirstHardenedChild, target.Got)
			},
		},
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
