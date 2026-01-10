package solana

import (
	"testing"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		index   int32
		address string
		private string
	}{
		{
			index:   0,
			address: "5jn67z6icfWYToBodAnn28CJENiq4R7CCEJn3RWQmpk6",
			private: "5znd4tyK9QPiCjxpQ94fYBgShKes3uWq5cwucSmFpYAh7DMpFPVhFTa7UH71rx5cLjJPb2piFExkMMaYJ8gUu6p6",
		},
		{
			index:   9,
			address: "8V8WRim5cGiFtJ8QrHU8Ve9VATi9DFpQA1axnDWAYvXk",
			private: "2wRBreTahtVmdgrad38XS7qn1JUu4w1kH28yGoqaQSXsowLdGXnpENAztF7xdn1afJuSdzHhrMPQ37ssKRZobRyt",
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
