package dogecoin

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
			address: "DDmog5ZadHMuQek9i3PMkpLQcPpBEPoy76",
			private: "QQvj71926WQGUSPu5hiyHoMzTWDW479hQuNa2KMQdegYpVYotg57",
		},
		{
			name:    "index9",
			index:   9,
			address: "DLzzpTjuHPbnL4MReKmHHyLtqhdTPYeUgi",
			private: "QTL7FHjHVuu9uJvSefFY6yQK12yViWAESXFxgdroqBKqMByZDJy8",
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
