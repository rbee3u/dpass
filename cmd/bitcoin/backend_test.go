package bitcoin

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestBackend(t *testing.T) {
	const mnemonic = "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		name    string
		purpose uint32
		account uint32
		change  uint32
		index   uint32
		address string
		private string
	}{
		{
			name:    "m/44'/0'/0'/0/0",
			purpose: purpose44,
			account: 0,
			change:  0,
			index:   0,
			address: "1EtWjpCUf349JLZV5e4oTyg9EW8jk2wb9E",
			private: "KzNh6kf7p7PBLB7FWxG6BmVerRSxR6Ui5SQNSL6bKWcSzQfxXvKG",
		},
		{
			name:    "m/44'/0'/0'/0/1",
			purpose: purpose44,
			account: 0,
			change:  0,
			index:   1,
			address: "1AH8nUNQfbXAbtGZWtFSqf9xjzNfaVCyRC",
			private: "L37fLtMHrwzCKL9AtNPmnso1q3eTnodsUEWwUoSUex9L5gdySsDM",
		},
		{
			name:    "m/44'/0'/0'/1/0",
			purpose: purpose44,
			account: 0,
			change:  1,
			index:   0,
			address: "151wc2xkjivCmgwMXH6L95x9iWZazgbMrW",
			private: "L3Sz1P491q22bvGc1Zc8t6X6CXFMa76i9797peqwPXiuYEGXZpj2",
		},
		{
			name:    "m/44'/0'/0'/1/1",
			purpose: purpose44,
			account: 0,
			change:  1,
			index:   1,
			address: "1MVrrjowifRWs5Avd6p6RQcUxv6yhWniZj",
			private: "L4GHToDuchiVLmVcDzdwLMa7rMCrUfTDsKxcymfS2sW1AZQcECBB",
		},
		{
			name:    "m/44'/0'/1'/0/0",
			purpose: purpose44,
			account: 1,
			change:  0,
			index:   0,
			address: "1GpfBSjvyda5wq96fb2myD9Wk4CmMHVZtr",
			private: "L2MgFujjyN6Q53EpbnTKBNMWF59rSEtfJvfJeRRvEzVT7yq6x38p",
		},
		{
			name:    "m/44'/0'/1'/0/1",
			purpose: purpose44,
			account: 1,
			change:  0,
			index:   1,
			address: "1G77XATt3yTBmrp8yrtgMjNWdeevjL35Xy",
			private: "L3LfREstGm5KnNZCpKcu93a8cHFD4xMvszXskZ9bQC2oV9TqZCAe",
		},
		{
			name:    "m/44'/0'/1'/1/0",
			purpose: purpose44,
			account: 1,
			change:  1,
			index:   0,
			address: "13jvQSgiTfbDj8qHQgD7ZLWgxmUTsrDJ2W",
			private: "L1fEUzSPgNQTVAbihhgxzZ9abcTnDsSFc3nu3AtgDv4d5PbMTLBg",
		},
		{
			name:    "m/44'/0'/1'/1/1",
			purpose: purpose44,
			account: 1,
			change:  1,
			index:   1,
			address: "1CikVT3R8ytkYuVybo2NmYjssqSyFGvL3M",
			private: "L1EC2Q45b9L7eCo6rMycxcLgjrAKd6CdC3iDrnJpoAks4kgpQnyq",
		},
		{
			name:    "m/49'/0'/0'/0/0",
			purpose: purpose49,
			account: 0,
			change:  0,
			index:   0,
			address: "36o36tMKQu8maT6Z1e5hFqP53ePC3NAXRq",
			private: "L2NjSH4S6KvANf9msxFcUCPnRe4k7HP1jBSMqtV3zHjJDnrYV6cY",
		},
		{
			name:    "m/49'/0'/0'/0/1",
			purpose: purpose49,
			account: 0,
			change:  0,
			index:   1,
			address: "3Lnh2hZJHy4p5mR1hyEWhCaFNFCeYnmJj8",
			private: "KzruZAqq5ZjzXK6bkSukQkrwRuNZRsfqBmcZXKURZ7x74pscsWCx",
		},
		{
			name:    "m/49'/0'/0'/1/0",
			purpose: purpose49,
			account: 0,
			change:  1,
			index:   0,
			address: "36sLXNkPWKwmELJH7KLxTxotJ8Lc6z6PAP",
			private: "L2b6P3XzeCmUuaWNDBXuroe6PyU3nwLWWy82tWXDS44iJpTeSZpf",
		},
		{
			name:    "m/49'/0'/0'/1/1",
			purpose: purpose49,
			account: 0,
			change:  1,
			index:   1,
			address: "34525yvqu6MdSzUzuJTbNXUxfSJNEqwLb7",
			private: "KxwPUwbdDbSnd13BTpoybmAXNfHt4vcttNRWhpk32tAQtKQgXHJ7",
		},
		{
			name:    "m/49'/0'/1'/0/0",
			purpose: purpose49,
			account: 1,
			change:  0,
			index:   0,
			address: "3DcwZncUpJ47tE32meXezHDbp4yucZmFxs",
			private: "L4VtGixevhbEkjjYXgcFYKm5VChcQFj1cJDYaUMqGeAFyuT8hwzQ",
		},
		{
			name:    "m/49'/0'/1'/0/1",
			purpose: purpose49,
			account: 1,
			change:  0,
			index:   1,
			address: "35xyEievNN7ieiwzcY24MmVb9Ch3oC9p8Z",
			private: "L4bVrfEPx3McmiQhubK1cQb4D4xveDjspVtujsbuWmBSzjf6HH3A",
		},
		{
			name:    "m/49'/0'/1'/1/0",
			purpose: purpose49,
			account: 1,
			change:  1,
			index:   0,
			address: "35Rb8XAYD6TxZcQTSP1Xq51w8FMcUE9mMU",
			private: "L194BdVEf3EXHPBY77Ki6VnRqginGtE5zPErkS9zkHRCqyEVjd3X",
		},
		{
			name:    "m/49'/0'/1'/1/1",
			purpose: purpose49,
			account: 1,
			change:  1,
			index:   1,
			address: "3Qz8r7hDwPYR266EeGKafqLJFQZxBt8bXt",
			private: "L5m5UPcp2awBH3zZdEWohXEFZWWnoCi5a7wsg7xJHY92GsxaMbUy",
		},
		{
			name:    "m/84'/0'/0'/0/0",
			purpose: purpose84,
			account: 0,
			change:  0,
			index:   0,
			address: "bc1qpeft30lweh28g9yaq20h0mfdjensap49l98jft",
			private: "L43KTUUsjTyZBN6Ach9LBPQiZf3RzdFGRR37ipve24uo8YVhEmgv",
		},
		{
			name:    "m/84'/0'/0'/0/1",
			purpose: purpose84,
			account: 0,
			change:  0,
			index:   1,
			address: "bc1q4sxvvfs3k6vjlm678087psvcvt592e4ck68udm",
			private: "L4CK8mvUxVz4ee4CNZC1HP1hSeM1jUzc1V2iYkzgpFDHX2QvzK6E",
		},
		{
			name:    "m/84'/0'/0'/1/0",
			purpose: purpose84,
			account: 0,
			change:  1,
			index:   0,
			address: "bc1q7dz7j8kz43puq7c07vqcde0f88ptamgtchartj",
			private: "L2AgdgCFrQoAUPa6oXQguWJNhgUwJMD9UcaC99frH9FNbPYVbdS7",
		},
		{
			name:    "m/84'/0'/0'/1/1",
			purpose: purpose84,
			account: 0,
			change:  1,
			index:   1,
			address: "bc1qx4k4d09l8n2dmtc5080dcd5v0zdmw8vt04fxqh",
			private: "KyxWwzXnTNSqrHcaDa6XF7bNGHX79Ute1DC7fP5DHK1zcXU47Vt6",
		},
		{
			name:    "m/84'/0'/1'/0/0",
			purpose: purpose84,
			account: 1,
			change:  0,
			index:   0,
			address: "bc1q27mwhllwt7u8ewvdqk6g7tra6qstsa2zaqu3ct",
			private: "L3oG6YtFK6E6TYRAsrBqCi9tPSxzN4GCPotVragwpnf8ghofyW4g",
		},
		{
			name:    "m/84'/0'/1'/0/1",
			purpose: purpose84,
			account: 1,
			change:  0,
			index:   1,
			address: "bc1qttgzj652fqttvrg8u80qynphn6k3ql7qqlezsh",
			private: "L1ZyDM28RhpMTcvFgqCjyaWr3U19tJPmv1SxufULzVktA2zfQ2CL",
		},
		{
			name:    "m/84'/0'/1'/1/0",
			purpose: purpose84,
			account: 1,
			change:  1,
			index:   0,
			address: "bc1qxg8gzuj2clxfs26mlzj3xeesudh9e8w0uus75l",
			private: "KxyJKUUcBdXCNt8uHKnBfJQ9LoP39Wb6KTBCNUqinZH4JFUrLUHy",
		},
		{
			name:    "m/84'/0'/1'/1/1",
			purpose: purpose84,
			account: 1,
			change:  1,
			index:   1,
			address: "bc1qdryhed96y3zkxzm9llh2p8s5zxdgv2jz832qdw",
			private: "Kx1DRGe5uVCg9hC5hTv38qrJBLws2E2EyedfhxFJgR6sh8fmNZHf",
		},
		{
			name:    "m/86'/0'/0'/0/0",
			purpose: purpose86,
			account: 0,
			change:  0,
			index:   0,
			address: "bc1p2k2y33zsuq50r0pmpkhe9fphmex35m5t8jes4paz09je9ukr8d6sntagnv",
			private: "L4eRxo4DNJ6jsJc3QBrt3iEBopKXnWgWgG4xUpU2jjqS5P3akERs",
		},
		{
			name:    "m/86'/0'/0'/0/1",
			purpose: purpose86,
			account: 0,
			change:  0,
			index:   1,
			address: "bc1p6am34g6dh03ese3cn9ldhcq9zk2ylvpw9tjq53599czjtfy2n8ms5nhaln",
			private: "KyMBNd5tKHFvwsm6CgHGjef8JXbzbmUi2B2xpeWogdvcr8sayH9D",
		},
		{
			name:    "m/86'/0'/0'/1/0",
			purpose: purpose86,
			account: 0,
			change:  1,
			index:   0,
			address: "bc1pra9klqtn75y5pg9rlxluh3e4qkr4q2xdnrce0ektqslzezjzr3xqz4yhjg",
			private: "L2ntPgoEgcPeFEWFWdv8PV44yeSRmnGN75vxQXNKustafpzeqsnF",
		},
		{
			name:    "m/86'/0'/0'/1/1",
			purpose: purpose86,
			account: 0,
			change:  1,
			index:   1,
			address: "bc1pyynep4w503c7s563gc5qnm0j255cqrpz8hc8ml365rm3v8h6604qltz5un",
			private: "KyVQB4Gv7fyy3YjyUgj5Fb9sTBpjaJvR5RGqbfbEVj3XrSFH8YEf",
		},
		{
			name:    "m/86'/0'/1'/0/0",
			purpose: purpose86,
			account: 1,
			change:  0,
			index:   0,
			address: "bc1p2jv2yxmge68xa4e3mfp5rgvw4586vanpqnpqrucgc6jw0pshs2lquf4326",
			private: "L3HKi3VjRXDZhBd6vLXDfWw7EguucNobtjGQ1yoHcpbt87cLU3Ma",
		},
		{
			name:    "m/86'/0'/1'/0/1",
			purpose: purpose86,
			account: 1,
			change:  0,
			index:   1,
			address: "bc1prppm5jc9ledkwt8a28ccgq03emwt727hl4yyrgt5spq97vavhjtsl9z4hg",
			private: "KyQCDQ9Mt6sphaCFgvjBoTCHavmAGd9p4dcYFNE9WhTSp1DSgjjM",
		},
		{
			name:    "m/86'/0'/1'/1/0",
			purpose: purpose86,
			account: 1,
			change:  1,
			index:   0,
			address: "bc1p9yh6avyls03s29nny4d5m0ye43hzv7kcnvpxt0eaze9w5gvap4uq04la0j",
			private: "L1yGs2WAajeHPoJ8YjZeVkx9cmUJxMD4jCT8FHHE7zkNtUWGwC7r",
		},
		{
			name:    "m/86'/0'/1'/1/1",
			purpose: purpose86,
			account: 1,
			change:  1,
			index:   1,
			address: "bc1pu5ntxx8tcqgx249m0p7z7waluuww9xjd0tf38yvyaavp6uzfewesqu9f63",
			private: "L2uKD8crKjiLDGq1xBA9axZ9dvr3TZ5VXhpAdJjwAd2as6Jvpjnh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := backendDefault()
			b.purpose = tt.purpose
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
