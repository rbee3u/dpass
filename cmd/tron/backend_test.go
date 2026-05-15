package tron

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
			b := &backend{account: tt.account, index: tt.index}
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
			b := &backend{account: tt.account, index: tt.index}
			b.reader, b.writer = tt.reader, tt.writer
			tt.requireErr(t, b.runE(nil, nil))
		})
	}
}
