package dogecoin

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
		change  uint32
		index   uint32
		address string
		private string
	}{
		{
			name:    "m/44'/3'/0'/0/0",
			account: 0,
			change:  0,
			index:   0,
			address: "DDmog5ZadHMuQek9i3PMkpLQcPpBEPoy76",
			private: "QQvj71926WQGUSPu5hiyHoMzTWDW479hQuNa2KMQdegYpVYotg57",
		},
		{
			name:    "m/44'/3'/0'/0/1",
			account: 0,
			change:  0,
			index:   1,
			address: "DTEz8RJkTpnCtbHW5S1x2j2mbB8baW4Gei",
			private: "QQXvGsrMeiqRaDECtJbAhsbpEHcn2ZMuJv2o5jjhMtMEx1vnwnBJ",
		},
		{
			name:    "m/44'/3'/0'/1/0",
			account: 0,
			change:  1,
			index:   0,
			address: "DQFNKwgvPYY2uuQer2Yv9MvNdNSYuZc5tK",
			private: "QSYiykrHvfjphx7DXYjzEoshP8NP6xVyMDjusDCvmJxj3AZyZQro",
		},
		{
			name:    "m/44'/3'/0'/1/1",
			account: 0,
			change:  1,
			index:   1,
			address: "DLMa4Twy4ZN6dJFHLvYzgcNveJ1Q2AGyUa",
			private: "QU6dk7gJqBjDazDNzYZ99T6T76kKsUwsrUcuX44bfcW2qy8PjF8X",
		},
		{
			name:    "m/44'/3'/1'/0/0",
			account: 1,
			change:  0,
			index:   0,
			address: "D9Ko359yhq3HVGu5sezVjsEyLLPreBZpNe",
			private: "QPVdu87VjzGxovHZrZEPh5HaC6qxSdyu7FtyX6eKhQZksg82EX5H",
		},
		{
			name:    "m/44'/3'/1'/0/1",
			account: 1,
			change:  0,
			index:   1,
			address: "DS7CFykcuJXxEufji2kDEWVTaEJv3yj9VG",
			private: "QRQemAngqxwdgU5Dkb48u8ZUksRuFdMB9pT8tTewVr6o3uuLV2YM",
		},
		{
			name:    "m/44'/3'/1'/1/0",
			account: 1,
			change:  1,
			index:   0,
			address: "DNMS4RcV6EHL6DpoNgs6fx5KRkj4HZKdVq",
			private: "QSAxCc6QdVHR628RfQ4PmhAuketHyKUpih442FdauwkCCNhpWUaW",
		},
		{
			name:    "m/44'/3'/1'/1/1",
			account: 1,
			change:  1,
			index:   1,
			address: "D9pjFrKTGjDpknrLp6p71Lns2FHpEmpcwB",
			private: "QSczdFD5jXHJ48bFLC5sBBx9UDmbDvNYqeErrbmZqDZ9W8R5pCHE",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			b.account = tt.account
			b.change = tt.change
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
				b.change = 2
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidChangeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(2), target.Got)
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
