package ethereum

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
			name:    "m/44'/60'/0'/0/0",
			account: 0,
			index:   0,
			address: "0xF2E68B8894e098AB6b5936906AB5ea73De03712E",
			private: "17348e94f527e08782ca41f4fc9cf702f143e397630ba8b6dc11d85a1e1dfaad",
		},
		{
			name:    "m/44'/60'/0'/0/1",
			account: 0,
			index:   1,
			address: "0x43246de308C6413aAB1Cb9c992455B96C0Dbfc30",
			private: "4a4ad554513ccd6439e00e5a7213f339a65e22fcde658d1fd8c54dea9de5cdce",
		},
		{
			name:    "m/44'/60'/1'/0/0",
			account: 1,
			index:   0,
			address: "0x8141beeA01261C4CaB97a8AaD6FB126C7f18F387",
			private: "1e92bc677f407294a1e9dbd1dd1610a1178f259d8d3c0296f110e61f2bfbb80f",
		},
		{
			name:    "m/44'/60'/1'/0/1",
			account: 1,
			index:   1,
			address: "0xD06390566B18D2c706ce64ab90Ba90f11649e04E",
			private: "4cf5a6aa64b1166d5a980c7d782a544b49178999b4cb695b6adb1f9363231d96",
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
