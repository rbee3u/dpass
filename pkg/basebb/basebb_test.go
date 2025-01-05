package basebb_test

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/rbee3u/dpass/pkg/basebb"
)

func TestTransform(t *testing.T) {
	for range 1000 {
		iBase, oBase, in, hasErr := ttGenerator()
		out, err := basebb.Transform(iBase, oBase, in)
		if err != nil {
			if hasErr {
				continue
			}
			t.Fatalf("failed to transform: %v", err)
		}
		gotIn, err := basebb.Transform(oBase, iBase, out)
		if err != nil {
			t.Fatalf("failed to transform back: %v", err)
		}
		if !bytes.Equal(gotIn, in) {
			t.Fatalf("got = %v, want = %v", gotIn, in)
		}
	}
}

func ttGenerator() (iBase uint32, oBase uint32, in []byte, hasErr bool) {
	iBase, oBase = rand.N[uint32](260), rand.N[uint32](260)
	if iBase < basebb.MinBase || iBase > basebb.MaxBase ||
		oBase < basebb.MinBase || oBase > basebb.MaxBase {
		hasErr = true
		return
	}
	in = make([]byte, rand.N(200))
	if len(in) != 0 && rand.N(10) == 0 {
		char := byte(rand.N(basebb.MaxBase))
		in[rand.N(len(in))] = char
		if uint32(char) >= iBase {
			hasErr = true
			return
		}
	}
	for i := range in {
		in[i] = byte(rand.N(iBase))
	}
	return
}
