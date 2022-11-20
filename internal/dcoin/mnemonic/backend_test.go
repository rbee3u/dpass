package mnemonic

import (
	"bytes"
	"compress/flate"
	"testing"
)

func TestCreateEntropyRandomly(t *testing.T) {
	for size := sizeMin; size <= sizeMax; size += sizeStep {
		if _, err := createEntropyRandomly(size); err != nil {
			t.Fatalf("failed to create entropy randomly: %v", err)
		}
	}

	var b []byte
	for i := 0; i < 1000000; i++ {
		entropy, err := createEntropyRandomly(sizeDefault)
		if err != nil {
			t.Fatalf("failed to create entropy randomly: %v", err)
		}

		b = append(b, entropy...)
	}

	var z bytes.Buffer
	f, _ := flate.NewWriter(&z, 9)
	_, _ = f.Write(b)
	_ = f.Close()

	if len(b) > z.Len() {
		t.Errorf("compressed: %d -> %d", len(b), z.Len())
	}
}
