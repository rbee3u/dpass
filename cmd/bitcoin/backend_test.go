package bitcoin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		name    string
		purpose uint32
		network string
		index   uint32
		address string
		private string
	}{
		{
			name:    "purpose44 mainnet index0",
			purpose: purpose44,
			network: networkMainNet,
			index:   0,
			address: "1EtWjpCUf349JLZV5e4oTyg9EW8jk2wb9E",
			private: "KzNh6kf7p7PBLB7FWxG6BmVerRSxR6Ui5SQNSL6bKWcSzQfxXvKG",
		},
		{
			name:    "purpose44 mainnet index9",
			purpose: purpose44,
			network: networkMainNet,
			index:   9,
			address: "1PT2nbAHWE4iqpbH8FG7tcPGaK9wFmazjE",
			private: "KwT8VzTg6TdXcc4DiQ254fHyHNtoYppbidm9m9k3DBV7BRX3MfkN",
		},
		{
			name:    "purpose44 regtest index0",
			purpose: purpose44,
			network: networkRegressionNet,
			index:   0,
			address: "mqAQq4XcdEBmJJTZAG8ryV9zyNfhNmuNuS",
			private: "cNLuYKhFv9hvTYfH6u65vchJWSvbEn2SY7ARDbUa37KAK9H1bqE7",
		},
		{
			name:    "purpose44 regtest index9",
			purpose: purpose44,
			network: networkRegressionNet,
			index:   9,
			address: "mx8aSRQjd8bWHLdFYejYHhiJN1CebTUif1",
			private: "cVeYXrqSB45DzYeurSgUYiNsFndTmj1WBZLa3hcWvRUCGd6FRGgt",
		},
		{
			name:    "purpose49 mainnet index0",
			purpose: purpose49,
			network: networkMainNet,
			index:   0,
			address: "36o36tMKQu8maT6Z1e5hFqP53ePC3NAXRq",
			private: "L2NjSH4S6KvANf9msxFcUCPnRe4k7HP1jBSMqtV3zHjJDnrYV6cY",
		},
		{
			name:    "purpose49 mainnet index9",
			purpose: purpose49,
			network: networkMainNet,
			index:   9,
			address: "37wAuysvKfSs4gDgWUC9PF3JLkJGSPaccL",
			private: "L4hNABeeKSSJU3RgkXarfmM1GBEU7YwegHZNqeB45FYk8eedCYtk",
		},
		{
			name:    "purpose49 regtest index0",
			purpose: purpose49,
			network: networkRegressionNet,
			index:   0,
			address: "2N6zD84MQ5AJ5VjJ1TfcRDXa28VWRf7wa2H",
			private: "cTzTfjLQ6QSYA2ewcXRF9bqHkfFsUVHCqaqten8sTsMD2Yg4MA8p",
		},
		{
			name:    "purpose49 regtest index9",
			purpose: purpose49,
			network: networkRegressionNet,
			index:   9,
			address: "2N9Ltc6XYJw4n4dvRbNzmMzbk2x4BP4APrt",
			private: "cSmhMGkmoDEsqG2DVYWYvHUCSChyHXa46nKcYyyWNUCT1kXMioBE",
		},
		{
			name:    "purpose84 mainnet index0",
			purpose: purpose84,
			network: networkMainNet,
			index:   0,
			address: "bc1qpeft30lweh28g9yaq20h0mfdjensap49l98jft",
			private: "L43KTUUsjTyZBN6Ach9LBPQiZf3RzdFGRR37ipve24uo8YVhEmgv",
		},
		{
			name:    "purpose84 mainnet index9",
			purpose: purpose84,
			network: networkMainNet,
			index:   9,
			address: "bc1qqfglwyjxt6tq046r5g4r80sykv2a38n6g9avlg",
			private: "KzobRPFXbur7FmAJXe2USrmrWXzfgCDXBXVwLshovYEU4hbnWVFn",
		},
		{
			name:    "purpose84 regtest index0",
			purpose: purpose84,
			network: networkRegressionNet,
			index:   0,
			address: "bcrt1q823gdstlg7zj9w2mhqnxuqrlyhnxtakkylxu8w",
			private: "cVdY1HfnxVop9LcbKRRp7guofgQ2WTa6KsyEKejVzT2oAKmsbtM1",
		},
		{
			name:    "purpose84 regtest index9",
			purpose: purpose84,
			network: networkRegressionNet,
			index:   9,
			address: "bcrt1qarc2clmmcj2gujhtrh5c3568v59nnjqsaj8z9t",
			private: "cNKY7rQ158hNMNEadp3Bysdpj4hvhKiqUAr6NeRDWruFMNVHbig9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pb := backendDefault()
			pb.purpose = tt.purpose
			pb.network = tt.network
			pb.index = tt.index
			address, err := pb.getResult(mnemonic)
			require.NoError(t, err)
			require.Equal(t, tt.address, address)
			sb := backendDefault()
			sb.purpose = tt.purpose
			sb.network = tt.network
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
				b.purpose = 99
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidPurposeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(99), target.Got)
				require.Equal(t, []uint32{purpose44, purpose49, purpose84}, target.Allowed)
			},
		},
		{
			name: "invalid network",
			setup: func(b *backend) {
				b.network = "fakenet"
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidNetworkError
				require.ErrorAs(t, err, &target)
				require.Equal(t, "fakenet", target.Got)
				require.Equal(t, []string{networkMainNet, networkRegressionNet, networkTestNet3, networkSimNet}, target.Allowed)
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
