package helper_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/helper"
)

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		hexKey   string
	}{
		{
			name:     "short password",
			password: []byte("_Short"),
			hexKey:   "66d93505bb87124fda05ac4ad3105e7b1cab52be2eb020c859a33f4769ad51c3",
		},
		{
			name:     "long password",
			password: []byte("_LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"),
			hexKey:   "73f32f797252f2756f4342205ff8944efa4cf62a4ce3b9a10e8a13bcdc3af1fa",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := helper.DeriveKey(tt.password)
			hexKey := hex.EncodeToString(key)
			require.Equal(t, tt.hexKey, hexKey)
		})
	}
}
