package dogecoin

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
			address: "DDmog5ZadHMuQek9i3PMkpLQcPpBEPoy76",
			private: "QQvj71926WQGUSPu5hiyHoMzTWDW479hQuNa2KMQdegYpVYotg57",
		},
		{
			index:   9,
			address: "DLzzpTjuHPbnL4MReKmHHyLtqhdTPYeUgi",
			private: "QTL7FHjHVuu9uJvSefFY6yQK12yViWAESXFxgdroqBKqMByZDJy8",
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
