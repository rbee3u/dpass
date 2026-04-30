package bitcoin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	getAddressAndSecret := func(t *testing.T, b *backend) (string, string) {
		t.Helper()
		address, err := b.getResult(mnemonic)
		require.NoError(t, err)
		secretBackend := *b
		secretBackend.secret = true
		private, err := secretBackend.getResult(mnemonic)
		require.NoError(t, err)
		return address, private
	}
	base := backendDefault()
	base.purpose = purpose44
	defaultAddress, defaultPrivate := getAddressAndSecret(t, base)
	tests := []struct {
		name           string
		purpose        uint32
		account        uint32
		change         uint32
		index          uint32
		decompress     bool
		address        string
		private        string
		compareDefault bool
	}{
		{
			name:    "purpose44 mainnet index0",
			purpose: purpose44,
			index:   0,
			address: "1EtWjpCUf349JLZV5e4oTyg9EW8jk2wb9E",
			private: "KzNh6kf7p7PBLB7FWxG6BmVerRSxR6Ui5SQNSL6bKWcSzQfxXvKG",
		},
		{
			name:    "purpose44 mainnet index9",
			purpose: purpose44,
			index:   9,
			address: "1PT2nbAHWE4iqpbH8FG7tcPGaK9wFmazjE",
			private: "KwT8VzTg6TdXcc4DiQ254fHyHNtoYppbidm9m9k3DBV7BRX3MfkN",
		},
		{
			name:    "purpose49 mainnet index0",
			purpose: purpose49,
			index:   0,
			address: "36o36tMKQu8maT6Z1e5hFqP53ePC3NAXRq",
			private: "L2NjSH4S6KvANf9msxFcUCPnRe4k7HP1jBSMqtV3zHjJDnrYV6cY",
		},
		{
			name:    "purpose49 mainnet index9",
			purpose: purpose49,
			index:   9,
			address: "37wAuysvKfSs4gDgWUC9PF3JLkJGSPaccL",
			private: "L4hNABeeKSSJU3RgkXarfmM1GBEU7YwegHZNqeB45FYk8eedCYtk",
		},
		{
			name:    "purpose84 mainnet index0",
			purpose: purpose84,
			index:   0,
			address: "bc1qpeft30lweh28g9yaq20h0mfdjensap49l98jft",
			private: "L43KTUUsjTyZBN6Ach9LBPQiZf3RzdFGRR37ipve24uo8YVhEmgv",
		},
		{
			name:    "purpose84 mainnet index9",
			purpose: purpose84,
			index:   9,
			address: "bc1qqfglwyjxt6tq046r5g4r80sykv2a38n6g9avlg",
			private: "KzobRPFXbur7FmAJXe2USrmrWXzfgCDXBXVwLshovYEU4hbnWVFn",
		},
		{
			name:    "purpose86 mainnet index0",
			purpose: purpose86,
			index:   0,
			address: "bc1p2k2y33zsuq50r0pmpkhe9fphmex35m5t8jes4paz09je9ukr8d6sntagnv",
			private: "L4eRxo4DNJ6jsJc3QBrt3iEBopKXnWgWgG4xUpU2jjqS5P3akERs",
		},
		{
			name:    "purpose86 mainnet index9",
			purpose: purpose86,
			index:   9,
			address: "bc1pdxcpq67uxecpfxpmaudewnrcv9xr2n3pvzg0ymkfm9v89rc939qq9z35jq",
			private: "L3vHcYWQcfFatLvMaJTkrBkbXfw9GeP9UbsPJCd6eiK3wy9KuGuC",
		},
		{
			name:           "purpose44 mainnet account1 changes output",
			purpose:        purpose44,
			account:        1,
			compareDefault: true,
		},
		{
			name:           "purpose44 mainnet change1 changes output",
			purpose:        purpose44,
			change:         1,
			compareDefault: true,
		},
		{
			name:           "purpose44 mainnet decompress changes output",
			purpose:        purpose44,
			decompress:     true,
			compareDefault: true,
		},
		{
			name:           "purpose86 mainnet account1 changes output",
			purpose:        purpose86,
			account:        1,
			compareDefault: true,
		},
		{
			name:           "purpose86 mainnet change1 changes output",
			purpose:        purpose86,
			change:         1,
			compareDefault: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			b.purpose = tt.purpose
			b.account = tt.account
			b.change = tt.change
			b.index = tt.index
			b.decompress = tt.decompress
			address, private := getAddressAndSecret(t, b)
			if tt.compareDefault {
				require.NotEqual(t, defaultAddress, address)
				require.NotEqual(t, defaultPrivate, private)
				return
			}
			require.Equal(t, tt.address, address)
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
				require.Equal(t, []uint32{purpose44, purpose49, purpose84, purpose86}, target.Allowed)
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
		{
			name: "decompress on purpose49",
			setup: func(b *backend) {
				b.purpose = purpose49
				b.decompress = true
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidDecompressPurposeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(purpose49), target.Purpose)
			},
		},
		{
			name: "decompress on purpose84",
			setup: func(b *backend) {
				b.purpose = purpose84
				b.decompress = true
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidDecompressPurposeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(purpose84), target.Purpose)
			},
		},
		{
			name: "decompress on purpose86",
			setup: func(b *backend) {
				b.purpose = purpose86
				b.decompress = true
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidDecompressPurposeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, uint32(purpose86), target.Purpose)
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
