package solana

import (
	"testing"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"

	tests := []struct {
		account uint32
		address string
		private string
	}{
		{
			account: 0,
			address: "2U37cGBQw7SV1FGtJ7hS2WEysirRprTeJxtg6QMqwV39",
			private: "4ur2z2DhVHNBTvNQqUVShkB52n9FoxnjnAvs39Q3cBZfjS3fH3gxDj8KNd2HifJQsUzjWAVufdjRoUv5tfDWsgJf",
		},
		{
			account: 9,
			address: "3cTedxyvDJUNhdH3AENbmKGyztWtKkrx7GX63trES7nz",
			private: "DmpKZdy3sdf4AJvMHgcHvanJu43SuTuGUBZcM5fsbU1bcydDTZDCiMDhcZHxnQ76aWDYdq4gnQexFan3mVcy8qG",
		},
	}

	for _, tt := range tests {
		pb := backendDefault()
		pb.account = tt.account
		address, err := pb.getResult(mnemonic)
		if err != nil {
			t.Fatalf("failed to get address: %v", err)
		}
		if address != tt.address {
			t.Errorf("address: got = %s, want = %s", address, tt.address)
		}
		sb := backendDefault()
		sb.account = tt.account
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
