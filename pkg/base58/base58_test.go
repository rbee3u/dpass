package base58_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/base58"
	"github.com/rbee3u/dpass/pkg/testx"
)

func TestEncodeDecode(t *testing.T) {
	tests := []struct {
		name string
		b256 []byte
		b58  string
	}{
		{
			name: "empty",
			b256: []byte{},
			b58:  "",
		},
		{
			name: "single zero byte",
			b256: []byte{0},
			b58:  "1",
		},
		{
			name: "single ff",
			b256: []byte{255},
			b58:  "5Q",
		},
		{
			name: "leading zeros",
			b256: []byte{0, 0, 0, 1},
			b58:  "1112",
		},
		{
			name: "hex bytes 0x0000287fb4cd",
			b256: []byte{0, 0, 40, 127, 180, 205},
			b58:  "11233QC4",
		},
		{
			name: "deadbeef",
			b256: []byte{222, 173, 190, 239},
			b58:  "6h8cQN",
		},
		{
			name: "hello world",
			b256: []byte("Hello World!"),
			b58:  "2NEpo7TZRRrLZSi2U",
		},
		{
			name: "the quick brown fox",
			b256: []byte("The quick brown fox jumps over the lazy dog."),
			b58:  "USm3fpXnKG5EUBx2ndxBDMPVciP5hGey2Jh4NDv6gmeo1LkMeiKrLJUUBk6Z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b58 := base58.Encode(tt.b256)
			require.Equal(t, tt.b58, b58)
			b256, err := base58.Decode(b58)
			require.NoError(t, err)
			testx.EqualSlice(t, tt.b256, b256)
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name       string
		b58        string
		requireErr func(*testing.T, error)
	}{
		{
			name: "zero character",
			b58:  "0invalid",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, base58.InvalidCharError{Offset: 0, Char: '0'}, target)
			},
		},
		{
			name: "uppercase O",
			b58:  "O",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, base58.InvalidCharError{Offset: 0, Char: 'O'}, target)
			},
		},
		{
			name: "invalid character after valid prefix",
			b58:  "abcOdef",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, base58.InvalidCharError{Offset: 3, Char: 'O'}, target)
			},
		},
		{
			name: "non-ascii byte",
			b58:  string([]byte{'a', 'b', 255}),
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, base58.InvalidCharError{Offset: 2, Char: 255}, target)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decoded, err := base58.Decode(tt.b58)
			require.Nil(t, decoded)
			tt.requireErr(t, err)
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
			name:     "alphabet too short",
			alphabet: "abc",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidAlphabetLengthError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 3, target.Length)
			},
		},
		{
			name:     "alphabet too long",
			alphabet: "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyzEXTRA",
			requireErr: func(t *testing.T, err error) {
				var target base58.InvalidAlphabetLengthError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 63, target.Length)
			},
		},
		{
			name:     "duplicate character",
			alphabet: "1234567899BCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz",
			requireErr: func(t *testing.T, err error) {
				var target base58.DuplicateAlphabetCharError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 9, target.Offset)
				require.Equal(t, byte('9'), target.Char)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoding, err := base58.NewEncoding(tt.alphabet)
			tt.requireErr(t, err)
			require.Nil(t, encoding)
		})
	}
}
