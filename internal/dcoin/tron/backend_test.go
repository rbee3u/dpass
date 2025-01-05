package tron

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
			address: "TFT56sLfzr8z1VsHrjfWDPTvmmNKq2YsLf",
			private: "0eca3714a60c1e0696a0b9414d427c71416dad7d65e78a7c36538fbc69e5ebf5",
		},
		{
			index:   9,
			address: "TWV9v9AruTYoM1BEpyQ4pkHgfiKRBnm1E6",
			private: "af3c32cd9f88036c564f1de3cc407bb0e60942714e323201f2dc90a2c7ca1fd9",
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
