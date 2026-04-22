package solana

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		name    string
		index   int32
		address string
		private string
	}{
		{
			name:    "index0",
			index:   0,
			address: "5jn67z6icfWYToBodAnn28CJENiq4R7CCEJn3RWQmpk6",
			private: "5znd4tyK9QPiCjxpQ94fYBgShKes3uWq5cwucSmFpYAh7DMpFPVhFTa7UH71rx5cLjJPb2piFExkMMaYJ8gUu6p6",
		},
		{
			name:    "index9",
			index:   9,
			address: "8V8WRim5cGiFtJ8QrHU8Ve9VATi9DFpQA1axnDWAYvXk",
			private: "2wRBreTahtVmdgrad38XS7qn1JUu4w1kH28yGoqaQSXsowLdGXnpENAztF7xdn1afJuSdzHhrMPQ37ssKRZobRyt",
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
				b.change = -2
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidChangeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, int32(-2), target.Got)
			},
		},
		{
			name: "invalid index",
			setup: func(b *backend) {
				b.index = -2
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidIndexError
				require.ErrorAs(t, err, &target)
				require.Equal(t, int32(-2), target.Got)
				require.False(t, target.RequireIgnore)
			},
		},
		{
			name: "change ignored but index not ignored",
			setup: func(b *backend) {
				b.change = changeIgnore
				b.index = 0
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidIndexError
				require.ErrorAs(t, err, &target)
				require.Equal(t, int32(0), target.Got)
				require.True(t, target.RequireIgnore)
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
