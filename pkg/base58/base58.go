// Package base58 implements Base58 encoders and decoders with configurable alphabets.
package base58

import "github.com/rbee3u/dpass/pkg/basebb"

var (
	// BitcoinEncoding is the Bitcoin-style Base58 alphabet (excludes 0/O/I/l).
	BitcoinEncoding = MustNewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	// FlickrEncoding swaps letter case for the same 58 symbols (Flickr/Base58 variant).
	FlickrEncoding = MustNewEncoding("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ")
)

// Encode encodes in using BitcoinEncoding.
func Encode(in []byte) string {
	return BitcoinEncoding.Encode(in)
}

// Decode decodes in using BitcoinEncoding.
func Decode(in string) ([]byte, error) {
	return BitcoinEncoding.Decode(in)
}

// Encoding is a Base58 codec for a specific 58-character alphabet.
type Encoding struct {
	encode string
	decode []byte
}

// MustNewEncoding is like NewEncoding but panics if alphabet is invalid.
func MustNewEncoding(alphabet string) *Encoding {
	encoding, err := NewEncoding(alphabet)
	if err != nil {
		panic(err)
	}
	return encoding
}

// NewEncoding builds an Encoding; alphabet must be 58 unique bytes.
func NewEncoding(alphabet string) (*Encoding, error) {
	if len(alphabet) != 58 {
		return nil, InvalidAlphabetLengthError{Length: len(alphabet)}
	}
	encoding := &Encoding{encode: alphabet, decode: make([]byte, 256)}
	for i := range len(alphabet) {
		if encoding.decode[alphabet[i]] != 0 {
			return nil, DuplicateAlphabetCharError{Offset: i, Char: alphabet[i]}
		}
		encoding.decode[alphabet[i]] = byte(i + 1)
	}
	return encoding, nil
}

// Encode returns the Base58 string for b256 using this alphabet.
func (e *Encoding) Encode(b256 []byte) string {
	in := make([]uint32, len(b256))
	for i := range b256 {
		in[i] = uint32(b256[i])
	}
	out, err := basebb.Transform(256, 58, in)
	if err != nil {
		// Unreachable: bases 256 and 58 are both >= MinBase, and every digit of
		// in is a byte value strictly less than 256.
		panic(err)
	}
	b58 := make([]byte, len(out))
	for i := range out {
		b58[i] = e.encode[out[i]]
	}
	return string(b58)
}

// Decode parses a Base58 string; invalid characters return InvalidCharError.
func (e *Encoding) Decode(b58 string) ([]byte, error) {
	in := make([]uint32, len(b58))
	for i := range len(b58) {
		if e.decode[b58[i]] == 0 {
			return nil, InvalidCharError{Offset: i, Char: b58[i]}
		}
		in[i] = uint32(e.decode[b58[i]] - 1)
	}
	out, err := basebb.Transform(58, 256, in)
	if err != nil {
		// Unreachable: bases 58 and 256 are both >= MinBase, and the decode
		// table guarantees every digit of in is in [0, 58).
		panic(err)
	}
	b256 := make([]byte, len(out))
	for i := range out {
		b256[i] = byte(out[i])
	}
	return b256, nil
}
