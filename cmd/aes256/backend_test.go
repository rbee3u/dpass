package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/testx"
)

func TestBackend(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "empty plaintext",
			plaintext: nil,
		},
		{
			name:      "short plaintext",
			plaintext: []byte("_Short"),
		},
		{
			name:      "long plaintext",
			plaintext: []byte("_LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testx.Stub(t, &readPassword, func(_ string) ([]byte, error) {
				return nil, nil
			})
			testx.Stub(t, &deriveKey, func(_ []byte) []byte {
				return []byte("a7b2fa8897cf785e2e5dbca7648617d4")
			})
			eb := &encryptBackend{nonce: rand.Reader}
			eb.reader = testx.NewReader(tt.plaintext, nil)
			ebWriter := testx.NewWriter(nil)
			eb.writer = ebWriter
			require.NoError(t, eb.runE(nil, nil))
			db := &decryptBackend{}
			db.reader = testx.NewReader(ebWriter.Bytes(), nil)
			dbWriter := testx.NewWriter(nil)
			db.writer = dbWriter
			require.NoError(t, db.runE(nil, nil))
			testx.EqualSlice(t, tt.plaintext, dbWriter.Bytes())
		})
	}
}

func TestEncryptBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		reader     *testx.Reader
		writer     *testx.Writer
		setup      func(*encryptBackend)
		requireErr func(*testing.T, error)
	}{
		{
			name:   "short nonce reader",
			reader: testx.NewReader(nil, nil),
			writer: testx.NewWriter(nil),
			setup: func(eb *encryptBackend) {
				eb.nonce = bytes.NewReader([]byte("bad-nonce"))
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("a7b2fa8897cf785e2e5dbca7648617d4")
				})
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read nonce")
				require.ErrorIs(t, err, io.ErrUnexpectedEOF)
			},
		},
		{
			name:   "invalid key length",
			reader: testx.NewReader(nil, nil),
			writer: testx.NewWriter(nil),
			setup: func(eb *encryptBackend) {
				eb.nonce = bytes.NewReader([]byte("ccc66c168049"))
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("bad-key")
				})
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to create AES cipher")
				var target aes.KeySizeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 7, int(target))
			},
		},
		{
			name:   "reader read failure",
			reader: testx.NewReader(nil, testx.ErrReadFailure),
			writer: testx.NewWriter(nil),
			setup:  func(_ *encryptBackend) {},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read plaintext")
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
		{
			name:   "writer write failure",
			reader: testx.NewReader(nil, nil),
			writer: testx.NewWriter(testx.ErrWriteFailure),
			setup: func(eb *encryptBackend) {
				eb.nonce = bytes.NewReader([]byte("ccc66c168049"))
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("a7b2fa8897cf785e2e5dbca7648617d4")
				})
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to write hex payload")
				require.ErrorIs(t, err, testx.ErrWriteFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testx.Stub(t, &readPassword, func(_ string) ([]byte, error) {
				return nil, nil
			})
			eb := &encryptBackend{}
			eb.reader, eb.writer = tt.reader, tt.writer
			tt.setup(eb)
			tt.requireErr(t, eb.runE(nil, nil))
		})
	}
}

func TestDecryptBackendErrors(t *testing.T) {
	tests := []struct {
		name       string
		reader     *testx.Reader
		writer     *testx.Writer
		setup      func(*decryptBackend)
		requireErr func(*testing.T, error)
	}{
		{
			name:   "invalid key length",
			reader: testx.NewReader([]byte("6363633636633136383034393b259b209b39ed3c78752632e2ca4050"), nil),
			writer: testx.NewWriter(nil),
			setup: func(db *decryptBackend) {
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("bad-key")
				})
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to create AES cipher")
				var target aes.KeySizeError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 7, int(target))
			},
		},
		{
			name:   "invalid hex payload",
			reader: testx.NewReader([]byte("6363633636633136383034393b259b209b39ed3c78752632e2ca40zz"), nil),
			writer: testx.NewWriter(nil),
			setup: func(db *decryptBackend) {
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("a7b2fa8897cf785e2e5dbca7648617d4")
				})
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to decode payload")
				var target hex.InvalidByteError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte('z'), byte(target))
			},
		},
		{
			name:   "short payload",
			reader: testx.NewReader([]byte("6363633636633136383034393b259b209b39ed3c78752632e2ca40"), nil),
			writer: testx.NewWriter(nil),
			setup: func(db *decryptBackend) {
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("a7b2fa8897cf785e2e5dbca7648617d4")
				})
			},
			requireErr: func(t *testing.T, err error) {
				var target invalidPayloadLengthError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 27, target.length)
				require.Equal(t, 28, target.minLength)
			},
		},
		{
			name:   "wrong key",
			reader: testx.NewReader([]byte("6363633636633136383034393b259b209b39ed3c78752632e2ca4050"), nil),
			writer: testx.NewWriter(nil),
			setup: func(db *decryptBackend) {
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("b7b2fa8897cf785e2e5dbca7648617d4")
				})
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to decrypt (wrong password or corrupted payload)")
			},
		},
		{
			name:   "reader read failure",
			reader: testx.NewReader(nil, testx.ErrReadFailure),
			writer: testx.NewWriter(nil),
			setup:  func(_ *decryptBackend) {},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to read hex payload")
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
		{
			name:   "writer write failure",
			reader: testx.NewReader([]byte("6363633636633136383034393b259b209b39ed3c78752632e2ca4050"), nil),
			writer: testx.NewWriter(testx.ErrWriteFailure),
			setup: func(db *decryptBackend) {
				testx.Stub(t, &deriveKey, func(_ []byte) []byte {
					return []byte("a7b2fa8897cf785e2e5dbca7648617d4")
				})
			},
			requireErr: func(t *testing.T, err error) {
				require.ErrorContains(t, err, "failed to write plaintext")
				require.ErrorIs(t, err, testx.ErrWriteFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testx.Stub(t, &readPassword, func(_ string) ([]byte, error) {
				return nil, nil
			})
			db := &decryptBackend{}
			db.reader, db.writer = tt.reader, tt.writer
			tt.setup(db)
			tt.requireErr(t, db.runE(nil, nil))
		})
	}
}
