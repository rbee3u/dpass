package base58

import (
	"bytes"
	"fmt"

	"github.com/rbee3u/dpass/pkg/basebb"
)

const (
	IBase uint32 = 256
	OBase uint32 = 58
)

type InvalidAlphabetError struct{ v string }

func (e InvalidAlphabetError) Error() string {
	return fmt.Sprintf("base58: invalid alphabet(%s)", e.v)
}

type InvalidCharError struct{ v byte }

func (e InvalidCharError) Error() string {
	return fmt.Sprintf("base58: invalid char(%#U)", e.v)
}

var (
	EncodeTransformer = basebb.MustNewTransformer(IBase, OBase)
	DecodeTransformer = basebb.MustNewTransformer(OBase, IBase)

	BitcoinEncoding = MustNewEncoding("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	FlickrEncoding  = MustNewEncoding("123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ")
)

func Encode(in []byte) string {
	return BitcoinEncoding.Encode(in)
}

func Decode(in string) ([]byte, error) {
	return BitcoinEncoding.Decode(in)
}

type Encoding struct {
	encode string
	decode []byte
}

func MustNewEncoding(alphabet string) *Encoding {
	encoding, err := NewEncoding(alphabet)
	if err != nil {
		panic(err)
	}
	return encoding
}

func NewEncoding(alphabet string) (*Encoding, error) {
	if size := len(alphabet); size != int(OBase) {
		return nil, InvalidAlphabetError{v: alphabet}
	}
	encoding := &Encoding{encode: alphabet}
	encoding.decode = bytes.Repeat([]byte{'\xff'}, int(IBase))
	for i := 0; i < len(alphabet); i++ { //nolint:intrange
		if encoding.decode[alphabet[i]] != '\xff' {
			return nil, InvalidAlphabetError{v: alphabet}
		}
		encoding.decode[alphabet[i]] = byte(i)
	}
	return encoding, nil
}

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

func (e *Encoding) Decode(_in string) ([]byte, error) {
	in := []byte(_in)
	for i := range in {
		if e.decode[in[i]] == '\xff' {
			return nil, InvalidCharError{v: in[i]}
		}
		in[i] = e.decode[in[i]]
	}
	out, err := DecodeTransformer.Transform(in)
	if err != nil {
		return nil, fmt.Errorf("failed to transform: %w", err)
	}
	return out, nil
}
