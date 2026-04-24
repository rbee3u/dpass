package sui

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
			address: "0xa3dd6730e699123c698ea2e5adb1c7ed423a0678d2b415313df494dd3b4cc4c8",
			private: "suiprivkey1qpxf0xl457682xmdw4j4yuuddx57xjh32964u0tfaawsjrdhm0r07hdvan6",
		},
		{
			name:    "index9",
			index:   9,
			address: "0x9b82160ca5e699e84bdf219f317b9d3987fc2a5bfb27fe47ed14dace7c0d1915",
			private: "suiprivkey1qzpfv4cvh9dr5kxkwx8v7eztrhnt9vzuktwc3hgmd0ja9s0tnaydy4s8ffd",
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
