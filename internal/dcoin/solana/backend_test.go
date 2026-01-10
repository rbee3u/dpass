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
			address: "5TkaGes9qsFAobA3iKyeGHaf5JNARzo72WX4iRvhN5yw",
			private: "35cXrG3kFDbQ3Pi32cj5ihXCkM9CPYZxcuJxcvvbaXZqGpLf64jdBjPT2wGG1yjR4SSxDoETB3VjwDaK5ZwnUb2M",
		},
		{
			account: 9,
			address: "89z6CUdzCicsSCWqW9sQCxf32YAK63wSiGCMFGaGLpFb",
			private: "5Qb2yH7s3aD2meWvBgSktureGAwqksMRJBNute2tZkDSCGr7JUmPiqTHhBtiA9CgSPzXXH5U7NfSTHTARY2At2hP",
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
