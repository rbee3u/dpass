package aes256

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBackend(t *testing.T) {
	tests := []struct {
		name      string
		key       []byte
		plaintext []byte
	}{
		{
			name:      "empty plaintext",
			key:       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			plaintext: nil, // or []byte("")
		},
		{
			name:      "short plaintext",
			key:       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			plaintext: []byte("_Short"),
		},
		{
			name:      "long plaintext",
			key:       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			plaintext: []byte("_LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eb := encryptBackendDefault()
			hexPayload, err := eb.encrypt(tt.key, tt.plaintext)
			require.NoError(t, err)
			db := decryptBackendDefault()
			plaintext, err := db.decrypt(tt.key, hexPayload)
			require.NoError(t, err)
			require.Equal(t, tt.plaintext, plaintext)
		})
	}
}

func TestBackendEncryptErrors(t *testing.T) {
	tests := []struct {
		name       string
		nonce      []byte
		key        []byte
		plaintext  []byte
		requireErr func(*testing.T, error)
	}{
		{
			name:      "short nonce reader",
			nonce:     []byte("bad-nonce"),
			key:       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			plaintext: []byte(""),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read nonce")
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			},
		},
		{
			name:      "invalid key length",
			nonce:     []byte("ccc66c168049"),
			key:       []byte("bad-key"),
			plaintext: []byte(""),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to create AES cipher")
				var target aes.KeySizeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 7, int(target))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eb := encryptBackendDefault()
			eb.nonceReader = bytes.NewReader(tt.nonce)
			hexPayload, err := eb.encrypt(tt.key, tt.plaintext)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, hexPayload)
		})
	}
}

func TestBackendDecryptErrors(t *testing.T) {
	tests := []struct {
		name       string
		key        []byte
		hexPayload []byte
		requireErr func(*testing.T, error)
	}{
		{
			name:       "invalid key length",
			key:        []byte("bad-key"),
			hexPayload: []byte("6363633636633136383034393b259b209b39ed3c78752632e2ca4050"),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to create AES cipher")
				var target aes.KeySizeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 7, int(target))
			},
		},
		{
			name:       "invalid hex payload",
			key:        []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			hexPayload: []byte("6363633636633136383034393b259b209b39ed3c78752632e2ca40zz"),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to decode payload")
				var target hex.InvalidByteError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte('z'), byte(target))
			},
		},
		{
			name:       "short payload",
			key:        []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			hexPayload: []byte("6363633636633136383034393b259b209b39ed3c78752632e2ca40"),
			requireErr: func(t *testing.T, err error) {
				var target invalidPayloadLengthError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 27, target.Got)
				require.Equal(t, 28, target.Min)
			},
		},
		{
			name:       "wrong key",
			key:        []byte("b7b2fa8897cf785e2e5dbca7648617d4"),
			hexPayload: []byte("6363633636633136383034393b259b209b39ed3c78752632e2ca4050"),
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to decrypt (wrong password or corrupted payload)")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := decryptBackendDefault()
			plaintext, err := db.decrypt(tt.key, tt.hexPayload)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, plaintext)
		})
	}
}
