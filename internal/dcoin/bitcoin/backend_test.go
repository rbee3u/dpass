package bitcoin

import "testing"

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"

	tests := []struct {
		purpose uint32
		network string
		index   uint32
		address string
		private string
	}{
		{
			purpose: purpose44,
			network: networkMainNet,
			index:   0,
			address: "1EtWjpCUf349JLZV5e4oTyg9EW8jk2wb9E",
			private: "KzNh6kf7p7PBLB7FWxG6BmVerRSxR6Ui5SQNSL6bKWcSzQfxXvKG",
		},
		{
			purpose: purpose44,
			network: networkMainNet,
			index:   9,
			address: "1PT2nbAHWE4iqpbH8FG7tcPGaK9wFmazjE",
			private: "KwT8VzTg6TdXcc4DiQ254fHyHNtoYppbidm9m9k3DBV7BRX3MfkN",
		},
		{
			purpose: purpose44,
			network: networkRegressionNet,
			index:   0,
			address: "mqAQq4XcdEBmJJTZAG8ryV9zyNfhNmuNuS",
			private: "cNLuYKhFv9hvTYfH6u65vchJWSvbEn2SY7ARDbUa37KAK9H1bqE7",
		},
		{
			purpose: purpose44,
			network: networkRegressionNet,
			index:   9,
			address: "mx8aSRQjd8bWHLdFYejYHhiJN1CebTUif1",
			private: "cVeYXrqSB45DzYeurSgUYiNsFndTmj1WBZLa3hcWvRUCGd6FRGgt",
		},
		{
			purpose: purpose49,
			network: networkMainNet,
			index:   0,
			address: "36o36tMKQu8maT6Z1e5hFqP53ePC3NAXRq",
			private: "L2NjSH4S6KvANf9msxFcUCPnRe4k7HP1jBSMqtV3zHjJDnrYV6cY",
		},
		{
			purpose: purpose49,
			network: networkMainNet,
			index:   9,
			address: "37wAuysvKfSs4gDgWUC9PF3JLkJGSPaccL",
			private: "L4hNABeeKSSJU3RgkXarfmM1GBEU7YwegHZNqeB45FYk8eedCYtk",
		},
		{
			purpose: purpose49,
			network: networkRegressionNet,
			index:   0,
			address: "2N6zD84MQ5AJ5VjJ1TfcRDXa28VWRf7wa2H",
			private: "cTzTfjLQ6QSYA2ewcXRF9bqHkfFsUVHCqaqten8sTsMD2Yg4MA8p",
		},
		{
			purpose: purpose49,
			network: networkRegressionNet,
			index:   9,
			address: "2N9Ltc6XYJw4n4dvRbNzmMzbk2x4BP4APrt",
			private: "cSmhMGkmoDEsqG2DVYWYvHUCSChyHXa46nKcYyyWNUCT1kXMioBE",
		},
		{
			purpose: purpose84,
			network: networkMainNet,
			index:   0,
			address: "bc1qpeft30lweh28g9yaq20h0mfdjensap49l98jft",
			private: "L43KTUUsjTyZBN6Ach9LBPQiZf3RzdFGRR37ipve24uo8YVhEmgv",
		},
		{
			purpose: purpose84,
			network: networkMainNet,
			index:   9,
			address: "bc1qqfglwyjxt6tq046r5g4r80sykv2a38n6g9avlg",
			private: "KzobRPFXbur7FmAJXe2USrmrWXzfgCDXBXVwLshovYEU4hbnWVFn",
		},
		{
			purpose: purpose84,
			network: networkRegressionNet,
			index:   0,
			address: "bcrt1q823gdstlg7zj9w2mhqnxuqrlyhnxtakkylxu8w",
			private: "cVdY1HfnxVop9LcbKRRp7guofgQ2WTa6KsyEKejVzT2oAKmsbtM1",
		},
		{
			purpose: purpose84,
			network: networkRegressionNet,
			index:   9,
			address: "bcrt1qarc2clmmcj2gujhtrh5c3568v59nnjqsaj8z9t",
			private: "cNKY7rQ158hNMNEadp3Bysdpj4hvhKiqUAr6NeRDWruFMNVHbig9",
		},
	}

	for _, tt := range tests {
		pb := backendDefault()
		pb.purpose = tt.purpose
		pb.network = tt.network
		pb.index = tt.index
		address, err := pb.getResult(mnemonic)
		if err != nil {
			t.Fatalf("failed to get address: %v", err)
		}
		if address != tt.address {
			t.Errorf("address: got = %s, want = %s", address, tt.address)
		}
		sb := backendDefault()
		sb.purpose = tt.purpose
		sb.network = tt.network
		sb.index = tt.index
		sb.secret = true
		private, err := sb.getResult(mnemonic)
		if err != nil {
			t.Fatalf("failed to get private: %v", err)
		}
		if private != tt.private {
			t.Errorf("private: got = %s, want = %s", private, tt.private)
		}
	}
}
