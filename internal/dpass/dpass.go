package dpass

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

func ReadPassword(prompt string) (password []byte, err error) {
	_, _ = fmt.Fprint(os.Stderr, prompt)
	fileDescriptor := syscall.Stdin
	if !term.IsTerminal(fileDescriptor) {
		var terminal *os.File
		if terminal, err = os.Open("/dev/tty"); err != nil {
			return nil, fmt.Errorf("failed to open terminal: %w", err)
		}
		defer func() {
			if e := terminal.Close(); e != nil && err == nil {
				err = fmt.Errorf("failed to close terminal: %w", e)
			}
		}()
		fileDescriptor = int(terminal.Fd())
	}
	if password, err = term.ReadPassword(fileDescriptor); err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}
	_, _ = fmt.Fprintln(os.Stderr)
	return password, nil
}

// DeriveKey derives a key from the password using Argon2id key derivation function.
// The salt, cost parameters and length of key are hardcoded, don't modify them!!!!!
func DeriveKey(password []byte) []byte {
	salt := []byte("github.com/rbee3u/dpass/internal/dpass.DeriveKey")
	return argon2.IDKey(password, salt, 16, 1*1024*1024, 2, 32)
}
