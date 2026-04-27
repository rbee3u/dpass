package bip3x

import "testing"

func StubHmacSha512ForTest(t *testing.T, fn func([]byte, []byte) ([]byte, []byte)) {
	t.Helper()

	old := hmacSha512
	hmacSha512 = fn

	t.Cleanup(func() {
		hmacSha512 = old
	})
}
