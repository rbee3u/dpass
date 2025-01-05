package sui

import (
	"testing"
)

func TestBackend(t *testing.T) {
	mnemonic := "daughter very gossip boil void ghost that obtain crew retreat obey direct brain bulb grow edge shield join hotel genius concert gain later account"
	tests := []struct {
		index   uint32
		address string
		private string
	}{
		{
			index:   0,
			address: "0xa3dd6730e699123c698ea2e5adb1c7ed423a0678d2b415313df494dd3b4cc4c8",
			private: "suiprivkey1qpxf0xl457682xmdw4j4yuuddx57xjh32964u0tfaawsjrdhm0r07hdvan6",
		},
		{
			index:   9,
			address: "0x9b82160ca5e699e84bdf219f317b9d3987fc2a5bfb27fe47ed14dace7c0d1915",
			private: "suiprivkey1qzpfv4cvh9dr5kxkwx8v7eztrhnt9vzuktwc3hgmd0ja9s0tnaydy4s8ffd",
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
