package sui

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/bip32"
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
			name:    "m/44'/784'/0'",
			account: 0,
			change:  changeIgnore,
			index:   indexIgnore,
			address: "0x0c4f8281ff96e97e84747d8d5bcad7989f1988ba6a6bb5f6f4b8ef29ea5d9b2c",
			private: "suiprivkey1qr2ujvan2xla7kk7mlre727x4e9547m04lpkwhzy0r2kkh32zpvu5yrydlj",
		},
		{
			name:    "m/44'/784'/0'/0'",
			account: 0,
			change:  0,
			index:   indexIgnore,
			address: "0x631fa722ec71f1f5e9ae40fdc25ebf21eabb76b2a023c42c67ce25bd92ad2244",
			private: "suiprivkey1qz4dgcv3nfnsm9yj7aj942grphn6dlf7g2kjflw6eg42jmrp5f3d53pxjr9",
		},
		{
			name:    "m/44'/784'/0'/0'/0'",
			account: 0,
			change:  0,
			index:   0,
			address: "0xa3dd6730e699123c698ea2e5adb1c7ed423a0678d2b415313df494dd3b4cc4c8",
			private: "suiprivkey1qpxf0xl457682xmdw4j4yuuddx57xjh32964u0tfaawsjrdhm0r07hdvan6",
		},
		{
			name:    "m/44'/784'/0'/0'/1'",
			account: 0,
			change:  0,
			index:   1,
			address: "0x019afdf5b8b348ed4a6370313b1bbb0916ebf2abdebfb58e229bba4b942824be",
			private: "suiprivkey1qqncvdrs2y79kya4hnaz02xrg8pc9dfh6mnsle0k49hkw4kad3q9ykk8axn",
		},
		{
			name:    "m/44'/784'/0'/1'",
			account: 0,
			change:  1,
			index:   indexIgnore,
			address: "0x34fa6577751e8ddc30c52c8114cbc284b2b96633f21d662e7e560f453c2f8f35",
			private: "suiprivkey1qp2z490fddu4s9cmw56ujnrm2jpjc9268pk5ecxdu8r62yfhz20esamrhmy",
		},
		{
			name:    "m/44'/784'/0'/1'/0'",
			account: 0,
			change:  1,
			index:   0,
			address: "0xf8824dae298de9cf1c9e58f096d5134c42a65bab826e4fd13fc11c41acb5f24a",
			private: "suiprivkey1qp6rvrj20w5crwv9u7vea87g620srpymr0pjnkapqxfnfc9sc244wn5zpcy",
		},
		{
			name:    "m/44'/784'/0'/1'/1'",
			account: 0,
			change:  1,
			index:   1,
			address: "0xd85d65cd93bc08146054f35192bc6eb1e88951124593c661f0deadad131b3777",
			private: "suiprivkey1qzlmd7kylkxq0hsqttq5la88mqgxeuezxh5lg7uv5m3rwkztltvr7ggddnw",
		},
		{
			name:    "m/44'/784'/1'",
			account: 1,
			change:  changeIgnore,
			index:   indexIgnore,
			address: "0xd0268fcd581d525c2ddd4ba90afb50b23646c7bd6a27d50861800a048e0c81ed",
			private: "suiprivkey1qpwdwrtqs00463g3gsdxyxmmdcf9hneuyna6tsz3s48sc06sf3klsn0vncx",
		},
		{
			name:    "m/44'/784'/1'/0'",
			account: 1,
			change:  0,
			index:   indexIgnore,
			address: "0x7c1a8ee60a9c26c5bfd8fa8b1704936f20864647e1a20104597e46f65c4241f6",
			private: "suiprivkey1qpmtgek6lpayl9vxxrmyqymyfuc73fguz2krewk3axjmakh67w9zzs3h24y",
		},
		{
			name:    "m/44'/784'/1'/0'/0'",
			account: 1,
			change:  0,
			index:   0,
			address: "0xd58d6329007bba632d6d49507efac5bd4ec6ce2804a28c939d46d6737be11e87",
			private: "suiprivkey1qz7kpctxqesed2un8j7vrqdm69yuwcfthatdems8hswam9lls4jlup6hhd2",
		},
		{
			name:    "m/44'/784'/1'/0'/1'",
			account: 1,
			change:  0,
			index:   1,
			address: "0x492208324b3083d34f836b4dba26ea064baeadd20dacf172567a4a7418f200f9",
			private: "suiprivkey1qq7m9t0v098hcxfnhfe7j9rz87kvhg748qeq8vynp0zns6v80swnup276sy",
		},
		{
			name:    "m/44'/784'/1'/1'",
			account: 1,
			change:  1,
			index:   indexIgnore,
			address: "0x021ad4c82a3c00b619efc75a3df7943d6b1df192818c30fe84c7d68d2a7184e6",
			private: "suiprivkey1qzwda2nmzv8a2h73kc3jt5p3hv0uus5ldz740yaz75vl87yn577eug8nzcs",
		},
		{
			name:    "m/44'/784'/1'/1'/0'",
			account: 1,
			change:  1,
			index:   0,
			address: "0xb05cc3dbcc91705149b5672051ec8f302b9cec12270e5e2c50f2bdba23e307bf",
			private: "suiprivkey1qpwmn445r042n0pfxqw9h93ew22kxgkymec8qjykdnl5d93pmyzxq3pcsez",
		},
		{
			name:    "m/44'/784'/1'/1'/1'",
			account: 1,
			change:  1,
			index:   1,
			address: "0xca46ae7a2a8036756027f57d5f5e3ae3491a42c33f0f5e5e4fc97e0a98e0a309",
			private: "suiprivkey1qrtuqn50qxul9p4v344ggxq3e6jx0grc4edtszwj9d67uf7a6p6xsq0kq4k",
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
				b.account = bip32.FirstHardenedChild
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidAccountError
				require.ErrorAs(t, err, &target)
				require.Equal(t, bip32.FirstHardenedChild, target.Got)
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
