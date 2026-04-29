package helper

import (
	"os"
	"testing"
)

func StubIsNotTerminal(t *testing.T, double func(int) bool) {
	Stub(t, &isNotTerminal, double)
}

func StubOpenTerminal(t *testing.T, double func() (*os.File, error)) {
	Stub(t, &openTerminal, double)
}

func StubCloseTerminal(t *testing.T, double func(*os.File) error) {
	Stub(t, &closeTerminal, double)
}

func StubReadPassword(t *testing.T, double func(int) ([]byte, error)) {
	Stub(t, &readPassword, double)
}

func Stub[T any](t *testing.T, target *T, double T) {
	double, *target = *target, double
	t.Cleanup(func() { *target = double })
}
