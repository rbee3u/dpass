// Package basebb converts big-endian digit streams between arbitrary bases.
package basebb

import (
	"fmt"
	"math"
)

// Supported input/output radix bounds.
const (
	// MinBase is the smallest radix supported for digit conversion.
	MinBase uint32 = 2
	// MaxBase is the largest radix supported (one byte per input digit).
	MaxBase uint32 = 256
)

// InvalidBaseError reports an input or output radix outside [MinBase, MaxBase].
type InvalidBaseError struct {
	Base uint32
}

func (e InvalidBaseError) Error() string {
	return fmt.Sprintf("basebb: invalid base (got %d, must be within [%d, %d])",
		e.Base, MinBase, MaxBase)
}

// InvalidCharError reports a digit byte >= iBase during Transform.
type InvalidCharError struct {
	Char byte
}

func (e InvalidCharError) Error() string {
	return fmt.Sprintf("basebb: invalid character %#U", e.Char)
}

// Transform converts in from iBase to oBase using a short-lived Transformer.
func Transform(iBase uint32, oBase uint32, in []byte) ([]byte, error) {
	transformer, err := NewTransformer(iBase, oBase)
	if err != nil {
		return nil, err
	}

	return transformer.Transform(in)
}

// Transformer reuses base-conversion parameters; ratio approximates output length from input length.
type Transformer struct {
	// iBase is the radix of the input digit stream.
	iBase uint32
	// oBase is the radix of the output digit stream.
	oBase uint32
	// ratio is log(iBase)/log(oBase), used to size the output buffer.
	ratio float64
}

// MustNewTransformer returns NewTransformer or panics on invalid bases.
func MustNewTransformer(iBase uint32, oBase uint32) *Transformer {
	transformer, err := NewTransformer(iBase, oBase)
	if err != nil {
		panic(err)
	}

	return transformer
}

// NewTransformer validates bases and precomputes the digit-length ratio.
func NewTransformer(iBase uint32, oBase uint32) (*Transformer, error) {
	if iBase < MinBase || iBase > MaxBase {
		return nil, InvalidBaseError{Base: iBase}
	}

	if oBase < MinBase || oBase > MaxBase {
		return nil, InvalidBaseError{Base: oBase}
	}

	ioRatio := math.Log(float64(iBase)) / math.Log(float64(oBase))

	return &Transformer{iBase: iBase, oBase: oBase, ratio: ioRatio}, nil
}

// Transform treats in as big-endian digits in iBase and returns big-endian digits in oBase (leading zeros preserved).
func (t *Transformer) Transform(in []byte) ([]byte, error) {
	zeros := 0
	for zeros < len(in) && in[zeros] == 0 {
		zeros++
	}

	out := make([]byte, zeros+int(math.Ceil(float64(len(in)-zeros)*t.ratio))+9)
	high1 := len(out)

	for i := range in {
		if uint32(in[i]) >= t.iBase {
			return nil, InvalidCharError{Char: in[i]}
		}

		carry, index := uint32(in[i]), len(out)-1
		for ; carry != 0 || index >= high1; index-- {
			carry += uint32(out[index]) * t.iBase
			carry, out[index] = carry/t.oBase, byte(carry%t.oBase)
		}

		high1 = index + 1
	}

	return out[high1-zeros:], nil
}
