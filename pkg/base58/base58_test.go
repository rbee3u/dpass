package base58_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/base58"
)

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		name    string
		decoded []byte
		encoded string
	}{
		{
			name:    "empty",
			decoded: []byte{},
			encoded: "",
		},
		{
			name:    "single zero byte",
			decoded: []byte{0},
			encoded: "1",
		},
		{
			name:    "leading zeros",
			decoded: []byte{0, 0, 0, 1},
			encoded: "1112",
		},
		{
			name:    "hello world",
			decoded: []byte("Hello World!"),
			encoded: "2NEpo7TZRRrLZSi2U",
		},
		{
			name:    "the quick brown fox",
			decoded: []byte("The quick brown fox jumps over the lazy dog."),
			encoded: "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z",
		},
		{
			name:    "hex bytes 0x0000287fb4cd",
			decoded: []byte{0x00, 0x00, 0x28, 0x7f, 0xb4, 0xcd},
			encoded: "11233QC4",
		},
		{
			name:    "single ff",
			decoded: []byte{0xff},
			encoded: "5Q",
		},
		{
			name:    "ascending bytes",
			decoded: []byte{0x01, 0x02, 0x03},
			encoded: "Ldp",
		},
		{
			name:    "all zeros",
			decoded: []byte{0, 0, 0, 0, 0},
			encoded: "11111",
		},
		{
			name:    "deadbeef",
			decoded: []byte{0xde, 0xad, 0xbe, 0xef},
			encoded: "6h8cQN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := base58.Encode(tt.decoded)
			require.Equal(t, tt.encoded, encoded)
			decoded, err := base58.Decode(encoded)
			require.NoError(t, err)
			require.Equal(t, tt.decoded, decoded)
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name       string
		encoded    string
		requireErr func(*testing.T, error)
	}{
		{
			name:    "zero character",
			encoded: "0invalid",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte('0'), target.Char)
			},
		},
		{
			name:    "uppercase O",
			encoded: "O",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte('O'), target.Char)
			},
		},
		{
			name:    "uppercase I",
			encoded: "I",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte('I'), target.Char)
			},
		},
		{
			name:    "lowercase l",
			encoded: "l",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, byte('l'), target.Char)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := base58.Decode(tt.encoded)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, decoded)
		})
	}
}

func TestNewEncodingErrors(t *testing.T) {
	tests := []struct {
		name       string
		alphabet   string
		requireErr func(*testing.T, error)
	}{
		{
			name:     "too short",
			alphabet: "abc",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidAlphabetError
				require.ErrorAs(t, err, &target)
				require.Equal(t, "abc", target.Alphabet)
			},
		},
		{
			name:     "too long",
			alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyzEXTRA",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidAlphabetError
				require.ErrorAs(t, err, &target)
			},
		},
		{
			name:     "duplicate character",
			alphabet: "1234567899BCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidAlphabetError
				require.ErrorAs(t, err, &target)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc, err := base58.NewEncoding(tt.alphabet)
			require.Error(t, err)
			tt.requireErr(t, err)
			require.Nil(t, enc)
		})
	}
}
