package ethereum

import "testing"

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"

	tests := []struct {
		index   uint32
		address string
		private string
	}{
		{
			index:   0,
			address: "0xF2E68B8894e098AB6b5936906AB5ea73De03712E",
			private: "17348e94f527e08782ca41f4fc9cf702f143e397630ba8b6dc11d85a1e1dfaad",
		},
		{
			index:   9,
			address: "0xcFaCBb2323A0529c90E4a25234a2Aa0a21328AfF",
			private: "0ab1781468d0da1f9021d7be5e9c6e78618f9709d4c043f56f7af0a96418bc39",
		},
	}

	for _, tt := range tests {
		pb := backendDefault()
		pb.index = tt.index
		address, err := pb.getResult(mnemonic)
		if err != nil {
			t.Fatalf("failed to get address: %v", err)
		}
		if address != tt.address {
			t.Errorf("address: got = %s, want = %s", address, tt.address)
		}
		sb := backendDefault()
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
