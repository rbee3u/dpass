package base58_test

import (
	"bytes"
	"math/rand/v2"
	"testing"

	"github.com/rbee3u/dpass/pkg/base58"
)

func TestTransform(t *testing.T) {
	for range 500 {
		in := ttGenerator()
		gotIn, err := base58.Decode(base58.Encode(in))
		if err != nil {
			t.Fatalf("failed to decode string: %v", err)
		}
		if !bytes.Equal(gotIn, in) {
			t.Fatalf("got = %v, want = %v", gotIn, in)
		}
	}
}

func ttGenerator() []byte {
	in := make([]byte, rand.N(100))
	for i := range in {
		in[i] = byte(rand.N(base58.IBase))
	}
	return in
}
