package solana

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
		change  int32
		index   int32
		address string
		private string
	}{
		{
			name:    "m/44'/501'/0'",
			account: 0,
			change:  changeIgnore,
			index:   indexIgnore,
			address: "5TkaGes9qsFAobA3iKyeGHaf5JNARzo72WX4iRvhN5yw",
			private: "35cXrG3kFDbQ3Pi32cj5ihXCkM9CPYZxcuJxcvvbaXZqGpLf64jdBjPT2wGG1yjR4SSxDoETB3VjwDaK5ZwnUb2M",
		},
		{
			name:    "m/44'/501'/0'/0'",
			account: 0,
			change:  0,
			index:   indexIgnore,
			address: "2U37cGBQw7SV1FGtJ7hS2WEysirRprTeJxtg6QMqwV39",
			private: "4ur2z2DhVHNBTvNQqUVShkB52n9FoxnjnAvs39Q3cBZfjS3fH3gxDj8KNd2HifJQsUzjWAVufdjRoUv5tfDWsgJf",
		},
		{
			name:    "m/44'/501'/0'/0'/0'",
			account: 0,
			change:  0,
			index:   0,
			address: "5jn67z6icfWYToBodAnn28CJENiq4R7CCEJn3RWQmpk6",
			private: "5znd4tyK9QPiCjxpQ94fYBgShKes3uWq5cwucSmFpYAh7DMpFPVhFTa7UH71rx5cLjJPb2piFExkMMaYJ8gUu6p6",
		},
		{
			name:    "m/44'/501'/0'/0'/1'",
			account: 0,
			change:  0,
			index:   1,
			address: "DhJqqNiuD5YUr5inGPhB39WgnFFi5UEEDQYs2vWMnQ5Y",
			private: "5M29Kp8MPMVtZJPhzj1HsZ5YSY4uqBgbpTcUE3gsRCBkTc9Bm8rAc3wUrhEPNF2yURDzSoLifwspTbCLCaws1bJi",
		},
		{
			name:    "m/44'/501'/0'/1'",
			account: 0,
			change:  1,
			index:   indexIgnore,
			address: "EAb8FSqBDmbRtVaxFAUxjmYvEGc6kTjy2dYHY4UxJyGG",
			private: "3Jy8qS2qiY37T4EfBCpKF9AdkqtHJvL6eWv1jeb47hHWTn4EHKEFu5MxaB2fs4KH4wqcT8XgvARAVQLvENFwoREk",
		},
		{
			name:    "m/44'/501'/0'/1'/0'",
			account: 0,
			change:  1,
			index:   0,
			address: "7BYjFaAKr3FttZCVa8RTs49QvkL3gKwDzoZokBCjf3gK",
			private: "4uLFucYs5ND4Wztc2x9B3EAYaTWcyXHgL3EXpTu47C2X98hn8yK5L3QwtJeYUbBdfW3aV52iaebLXHAx99DNQV6f",
		},
		{
			name:    "m/44'/501'/0'/1'/1'",
			account: 0,
			change:  1,
			index:   1,
			address: "SdzusbSAeNoB7xTbVEqjAyA2kXWk1of5R6pmBtVLaig",
			private: "2kYJSwton8KFa8nedKhjdXPhFccUhpRuWAfRvoDBEc6uJZ43ocVieppSjNy9KK5j79xArRAimosHkyfoxsbWzTaL",
		},
		{
			name:    "m/44'/501'/1'",
			account: 1,
			change:  changeIgnore,
			index:   indexIgnore,
			address: "DWdjvLRQNG6uTy3e5Pko4igXkgkPesQJ1FSxe2TnCxDk",
			private: "3Wq48ouL1AoKtKMTjcb62NkS2MicnQRevGZbTupXTNuPPDfLqtGcbmuGpi9BfiBoB2aEwkjpky6V2dYNp4DXCmWE",
		},
		{
			name:    "m/44'/501'/1'/0'",
			account: 1,
			change:  0,
			index:   indexIgnore,
			address: "56zdGJPCS9KExVfHnMCuLvVCpWRfboS4gkGqBqgrScvs",
			private: "4shCEf42nYeB4qN9zj2sTtuyWuCyUJiymXcubfYy7PcugUhp9dc1JpPPMLhRvBtLDRB9eHKSNq4ELUx5ZXDmW3JF",
		},
		{
			name:    "m/44'/501'/1'/0'/0'",
			account: 1,
			change:  0,
			index:   0,
			address: "9Jbr8Mp5PvbZwgMpjjcvwnxVxUuyQ9tfwrPXYYGfoR7N",
			private: "4v9ZiXccxN4ThdugmKADqBP7vBM9FW9KPM5Fsa2XfhNJXSfK9hrqRdswXJ2HCwACFWxZBZNHM6exhhdgJL2ngzYp",
		},
		{
			name:    "m/44'/501'/1'/0'/1'",
			account: 1,
			change:  0,
			index:   1,
			address: "AGfLp5XTHnjMWHwdYCFqW9J4NDJCRx5h6Q6qfjcM2829",
			private: "34Gh9yti1LHY6Gg6nrHnnqVd7CwZ2EWqiaNu7PEh7PVhapevJiXawt9jpBfDSVP2rtxc8YMFQ3srmzjzof9qc8qs",
		},
		{
			name:    "m/44'/501'/1'/1'",
			account: 1,
			change:  1,
			index:   indexIgnore,
			address: "2srpQS5PZBjTdgrn5D8w7jLVwW43aCfXgJPtCaQ3cJrp",
			private: "2kLRxrk2DwQj1n3qXqT4ccSy3tjnydnnagKJS3FQGVNwjXxNojhH881tbrgRiydLeUTPpdmNWZiPeX68e9rGX3LG",
		},
		{
			name:    "m/44'/501'/1'/1'/0'",
			account: 1,
			change:  1,
			index:   0,
			address: "28Jmcfr35A7UhJrbLW8qx3oX84fB9nSKSbUQdLj7ZWLA",
			private: "43UgWDFMEBR9EpxpmvVC7a7XpdKdAeigtq7hupDzYvxbBUHsEiD8oMqecYxUFHYEDksad9n66u9MfUJdWYJ9DhqC",
		},
		{
			name:    "m/44'/501'/1'/1'/1'",
			account: 1,
			change:  1,
			index:   1,
			address: "7jpn5ocfxEPfeZtniRJUGpSbVX9ECssAxh3bj371tnZp",
			private: "3WJhteA4exbo6FNU6BBYwVPfCn6BidZRFG8jwSrEbqB9aKSQ85oY2un3ZLK3kEjRMkMVvcz9MW5Znywmt75uEpjL",
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
