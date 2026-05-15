package helper

import (
	"os"
	"testing"

	"github.com/rbee3u/dpass/pkg/testx"
)

func StubIsTerminal(t *testing.T, double func(int) bool) {
	testx.Stub(t, &isTerminal, double)
}

func StubOpenTerminal(t *testing.T, double func() (*os.File, error)) {
	testx.Stub(t, &openTerminal, double)
}

func StubCloseTerminal(t *testing.T, double func(*os.File) error) {
	testx.Stub(t, &closeTerminal, double)
}

func StubReadPassword(t *testing.T, double func(int) ([]byte, error)) {
	testx.Stub(t, &readPassword, double)
}
