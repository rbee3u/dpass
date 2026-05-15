package dogecoin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip32"
	"github.com/rbee3u/dpass/pkg/testx"
)

func TestBackend(t *testing.T) {
	mnemonic := []byte("daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account")
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
			b := &backend{account: tt.account, change: tt.change, index: tt.index}
			b.reader = testx.NewReader(mnemonic, nil)
			bWriter := testx.NewWriter(nil)
			b.writer = bWriter
			require.NoError(t, b.runE(nil, nil))
			require.Equal(t, tt.address, bWriter.String())
			b.secret = true
			b.reader = testx.NewReader(mnemonic, nil)
			bWriter = testx.NewWriter(nil)
			b.writer = bWriter
			require.NoError(t, b.runE(nil, nil))
			require.Equal(t, tt.private, bWriter.String())
		})
	}
}

func TestBackendErrors(t *testing.T) {
	mnemonic := []byte("daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account")
	tests := []struct {
		name       string
		account    uint32
		change     uint32
		index      uint32
		reader     *testx.Reader
		writer     *testx.Writer
		requireErr func(*testing.T, error)
	}{
		{
			name:    "invalid account",
			account: bip32.FirstHardenedChild,
			reader:  testx.NewReader(mnemonic, nil),
			writer:  testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target invalidAccountError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip32.FirstHardenedChild, target.account)
			},
		},
		{
			name:   "invalid change",
			change: 2,
			reader: testx.NewReader(mnemonic, nil),
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target invalidChangeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(2), target.change)
			},
		},
		{
			name:   "invalid index",
			index:  bip32.FirstHardenedChild,
			reader: testx.NewReader(mnemonic, nil),
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				var target invalidIndexError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip32.FirstHardenedChild, target.index)
			},
		},
		{
			name:   "reader read failure",
			reader: testx.NewReader(nil, testx.ErrReadFailure),
			writer: testx.NewWriter(nil),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read mnemonic")
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
		{
			name:   "writer write failure",
			reader: testx.NewReader(mnemonic, nil),
			writer: testx.NewWriter(testx.ErrWriteFailure),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to write result")
				require.ErrorIs(t, err, testx.ErrWriteFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &backend{account: tt.account, change: tt.change, index: tt.index}
			b.reader, b.writer = tt.reader, tt.writer
			tt.requireErr(t, b.runE(nil, nil))
		})
	}
}
