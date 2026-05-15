package bip32

import (
	"testing"

	"github.com/rbee3u/dpass/pkg/testx"
)

func StubHmacSha512(t *testing.T, double func([]byte, []byte) ([]byte, []byte)) {
	testx.Stub(t, &hmacSha512, double)
}
