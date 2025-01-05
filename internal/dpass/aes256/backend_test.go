package aes256

import (
	"bytes"
	"io"
	"testing"
)

func TestEncryptBackend(t *testing.T) {
	tests := []struct {
		nonceReader               io.Reader
		key                       []byte
		plaintext                 []byte
		encodedNonceAndCiphertext []byte
	}{
		{
			nonceReader:               bytes.NewReader([]byte("ccc66c168049")),
			key:                       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			plaintext:                 []byte("_Short"),
			encodedNonceAndCiphertext: []byte("63636336366331363830343989f0525931a606f3d22a1fb9248b2444e8a2db37cfe3"),
		},
		{
			nonceReader:               bytes.NewReader([]byte("ccc66c168049")),
			key:                       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			plaintext:                 []byte("_LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"),
			encodedNonceAndCiphertext: []byte("63636336366331363830343989ef5558249eba6379f1532d03952d41300a41fef33579cac343d621224bde51bfbe9730ae2c11d54dfdb905884cc7a4624b9a7a7db954ebae10a07f4eab0cdc67b01b32e426d086b267f983b53db9ee75"),
		},
	}
	for _, tt := range tests {
		eb := encryptBackendDefault()
		eb.nonceReader = tt.nonceReader
		encodedNonceAndCiphertext, err := eb.encrypt(tt.key, tt.plaintext)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}
		if !bytes.Equal(encodedNonceAndCiphertext, tt.encodedNonceAndCiphertext) {
			t.Errorf("got = %s, want = %s", encodedNonceAndCiphertext, tt.encodedNonceAndCiphertext)
		}
	}
}

func TestDecryptBackend(t *testing.T) {
	tests := []struct {
		key                       []byte
		encodedNonceAndCiphertext []byte
		plaintext                 []byte
	}{
		{
			key:                       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			encodedNonceAndCiphertext: []byte("63636336366331363830343989f0525931a606f3d22a1fb9248b2444e8a2db37cfe3"),
			plaintext:                 []byte("_Short"),
		},
		{
			key:                       []byte("a7b2fa8897cf785e2e5dbca7648617d4"),
			encodedNonceAndCiphertext: []byte("63636336366331363830343989ef5558249eba6379f1532d03952d41300a41fef33579cac343d621224bde51bfbe9730ae2c11d54dfdb905884cc7a4624b9a7a7db954ebae10a07f4eab0cdc67b01b32e426d086b267f983b53db9ee75"),
			plaintext:                 []byte("_LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"),
		},
	}
	for _, tt := range tests {
		db := decryptBackendDefault()
		plaintext, err := db.decrypt(tt.key, tt.encodedNonceAndCiphertext)
		if err != nil {
			t.Fatalf("failed to decrypt: %v", err)
		}
		if !bytes.Equal(plaintext, tt.plaintext) {
			t.Errorf("got = %v, want = %v", plaintext, tt.plaintext)
		}
	}
}
