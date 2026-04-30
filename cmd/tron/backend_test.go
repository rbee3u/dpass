package tron

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	const mnemonic = "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		name    string
		account uint32
		index   uint32
		address string
		private string
	}{
		{
			name:    "m/44'/195'/0'/0/0",
			account: 0,
			index:   0,
			address: "TFT56sLfzr8z1VsHrjfWDPTvmmNKq2YsLf",
			private: "0eca3714a60c1e0696a0b9414d427c71416dad7d65e78a7c36538fbc69e5ebf5",
		},
		{
			name:    "m/44'/195'/0'/0/1",
			account: 0,
			index:   1,
			address: "THScfgwhyZcb9JdwUAcdkL4fmTtRQgnX6J",
			private: "8a17cdb6193826f51993d420e2910b21261af7da2c90a17c0572c7d5396baa38",
		},
		{
			name:    "m/44'/195'/1'/0/0",
			account: 1,
			index:   0,
			address: "TWffzqGSZKmDfoJJNnLqKjYYmQYwv96bQs",
			private: "589f84967d81a958dd8e00cce9e14c1aee1478586097a681eb3747aeeafc443e",
		},
		{
			name:    "m/44'/195'/1'/0/1",
			account: 1,
			index:   1,
			address: "TTavreTH4YETr2teogjmZ9wF4gw9N9J29o",
			private: "baa8f82632e2027ebdc7f8a2fa9cc06431d22a694f11ed65a1e6a9eb6108e7b6",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			b.account = tt.account
			b.index = tt.index
			address, err := b.getResult(mnemonic)
			require.NoError(t, err)
			require.Equal(t, tt.address, address)
			b.secret = true
			private, err := b.getResult(mnemonic)
			require.NoError(t, err)
			require.Equal(t, tt.private, private)
		})
	}
}

func TestBackendErrors(t *testing.T) {
	const mnemonic = "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
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
