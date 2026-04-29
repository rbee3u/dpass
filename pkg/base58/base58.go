// Package base58 implements Base58 encoders and decoders with configurable alphabets.
package base58

import (
	"bytes"
	"fmt"

	"github.com/rbee3u/dpass/pkg/basebb"
)

// Input/output radices used by Base58 conversion.
const (
	// IBase is the radix of raw input bytes before Base58 conversion.
	IBase uint32 = 256
	// OBase is the radix of the Base58 digit stream (alphabet size).
	OBase uint32 = 58
)

// InvalidAlphabetError reports a non-58-length or duplicate-character alphabet.
type InvalidAlphabetError struct {
	// Alphabet is the rejected alphabet string.
	Alphabet string
}

func (e InvalidAlphabetError) Error() string {
	return fmt.Sprintf("base58: invalid alphabet %q", e.Alphabet)
}

// InvalidCharError reports an input byte not present in the encoding alphabet.
type InvalidCharError struct {
	// Char is the first byte not present in the encoding alphabet.
	Char byte
}

func (e InvalidCharError) Error() string {
	return fmt.Sprintf("base58: invalid character %#U", e.Char)
}

// Shared transformers and standard Base58 alphabets.
var (
	// EncodeTransformer converts big-endian bytes to Base58 digit indices (0..57).
	EncodeTransformer = basebb.MustNewTransformer(IBase, OBase)
	// DecodeTransformer converts Base58 digit indices back to bytes.
	DecodeTransformer = basebb.MustNewTransformer(OBase, IBase)
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
	// encode lists alphabet symbols in digit order (index 0..57).
	encode string
	// decode maps ASCII symbol -> digit 0..57; 0xff means invalid
	decode []byte
}

// MustNewEncoding returns NewEncoding(alphabet) or panics on error.
func MustNewEncoding(alphabet string) *Encoding {
	encoding, err := NewEncoding(alphabet)
	if err != nil {
		panic(err)
	}
	return encoding
}

// NewEncoding builds an Encoding; alphabet must be 58 unique bytes.
func NewEncoding(alphabet string) (*Encoding, error) {
	if size := len(alphabet); size != int(OBase) {
		return nil, InvalidAlphabetError{Alphabet: alphabet}
	}
	encoding := &Encoding{encode: alphabet}
	encoding.decode = bytes.Repeat([]byte{255}, int(IBase))
	for i := 0; i < len(alphabet); i++ {
		if encoding.decode[alphabet[i]] != 255 {
			return nil, InvalidAlphabetError{Alphabet: alphabet}
		}
		encoding.decode[alphabet[i]] = byte(i)
	}
	return encoding, nil
}

// Encode returns the Base58 string for in using this alphabet.
func (e *Encoding) Encode(in []byte) string {
	out, err := EncodeTransformer.Transform(in)
	if err != nil {
		panic(err)
	}
	for i := range out {
		out[i] = e.encode[out[i]]
	}
	return string(out)
}

// Decode parses a Base58 string; invalid characters return InvalidCharError.
func (e *Encoding) Decode(_in string) ([]byte, error) {
	in := []byte(_in)
	for i := range in {
		if e.decode[in[i]] == 255 {
			return nil, InvalidCharError{Char: in[i]}
		}
		in[i] = e.decode[in[i]]
	}
	out, err := DecodeTransformer.Transform(in)
	if err != nil {
		return nil, fmt.Errorf("failed to transform: %w", err)
	}
	return out, nil
}
