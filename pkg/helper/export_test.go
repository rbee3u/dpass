package helper

import (
	"os"
	"testing"
)

func StubPasswordDependenciesForTest(
	t *testing.T,
	isTerminal func(int) bool,
	readPassword func(int) ([]byte, error),
	open func() (*os.File, error),
) {
	t.Helper()

	oldIsTerminal := termIsTerminal
	oldReadPassword := termReadPassword
	oldOpenTerminal := openTerminal

	if isTerminal != nil {
		termIsTerminal = isTerminal
	}
	if readPassword != nil {
		termReadPassword = readPassword
	}
	if open != nil {
		openTerminal = open
	}

	t.Cleanup(func() {
		termIsTerminal = oldIsTerminal
		termReadPassword = oldReadPassword
		openTerminal = oldOpenTerminal
	})
}
