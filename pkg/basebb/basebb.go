package basebb

import (
	"fmt"
	"math"
)

const (
	MinBase uint32 = 2
	MaxBase uint32 = 256
)

type InvalidBaseError struct{ v uint32 }

func (e InvalidBaseError) Error() string {
	return fmt.Sprintf("basebb: invalid base(%v)", e.v)
}

type InvalidCharError struct{ v byte }

func (e InvalidCharError) Error() string {
	return fmt.Sprintf("basebb: invalid char(%#U)", e.v)
}

func Transform(iBase uint32, oBase uint32, in []byte) ([]byte, error) {
	transformer, err := NewTransformer(iBase, oBase)
	if err != nil {
		return nil, err
	}
	return transformer.Transform(in)
}

type Transformer struct {
	iBase uint32
	oBase uint32
	ratio float64
}

func MustNewTransformer(iBase uint32, oBase uint32) *Transformer {
	transformer, err := NewTransformer(iBase, oBase)
	if err != nil {
		panic(err)
	}
	return transformer
}

func NewTransformer(iBase uint32, oBase uint32) (*Transformer, error) {
	if iBase < MinBase || iBase > MaxBase {
		return nil, InvalidBaseError{v: iBase}
	}
	if oBase < MinBase || oBase > MaxBase {
		return nil, InvalidBaseError{v: oBase}
	}
	ioRatio := math.Log(float64(iBase)) / math.Log(float64(oBase))
	return &Transformer{iBase: iBase, oBase: oBase, ratio: ioRatio}, nil
}

func (t *Transformer) Transform(in []byte) ([]byte, error) {
	zeros := 0
	for ; zeros < len(in) && in[zeros] == 0; zeros++ { //nolint:revive
	}
	out := make([]byte, zeros+int(math.Ceil(float64(len(in)-zeros)*t.ratio))+9)
	high1 := len(out)
	for i := range in {
		if uint32(in[i]) >= t.iBase {
			return nil, InvalidCharError{v: in[i]}
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
