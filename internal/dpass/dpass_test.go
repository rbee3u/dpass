package dpass_test

import (
	"encoding/hex"
	"testing"

	"github.com/rbee3u/dpass/internal/dpass"
)

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		password []byte
		key0x    string
	}{
		{
			password: []byte("_Short"),
			key0x:    "66d93505bb87124fda05ac4ad3105e7b1cab52be2eb020c859a33f4769ad51c3",
		},
		{
			password: []byte("_LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"),
			key0x:    "73f32f797252f2756f4342205ff8944efa4cf62a4ce3b9a10e8a13bcdc3af1fa",
		},
	}
	for _, tt := range tests {
		key0x := hex.EncodeToString(dpass.DeriveKey(tt.password))
		if key0x != tt.key0x {
			t.Errorf("got = %s, want = %s", key0x, tt.key0x)
		}
	}
}
