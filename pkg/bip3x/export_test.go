package bip3x

import "testing"

func StubHmacSha512(t *testing.T, double func([]byte, []byte) ([]byte, []byte)) {
	Stub(t, &hmacSha512, double)
}

func Stub[T any](t *testing.T, target *T, double T) {
	double, *target = *target, double
	t.Cleanup(func() { *target = double })
}
