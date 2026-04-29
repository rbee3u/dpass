// Package helper provides shared CLI helpers for passwords and key derivation.
package helper

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

var (
	isNotTerminal = func(fd int) bool { return !term.IsTerminal(fd) }
	openTerminal  = func() (*os.File, error) { return os.Open("/dev/tty") }
	closeTerminal = func(terminal *os.File) error { return terminal.Close() }
	readPassword  = term.ReadPassword
)

// ReadPassword prints prompt, reads a line without echo when possible, and appends a
// trailing newline after a successful read.
// When stdin is not a TTY, it reads from /dev/tty so callers can keep stdin reserved
// for piped command data.
func ReadPassword(prompt string) (password []byte, err error) {
	fd, promptWriter := syscall.Stdin, io.Writer(os.Stderr)
	if isNotTerminal(fd) {
		var terminal *os.File
		if terminal, err = openTerminal(); err != nil {
			return nil, fmt.Errorf("failed to open terminal for password input: %w", err)
		}
		defer func() {
			if e := closeTerminal(terminal); e != nil && err == nil {
				password = nil
				err = fmt.Errorf("failed to close terminal used for password input: %w", e)
			}
		}()
		fd, promptWriter = int(terminal.Fd()), terminal
	}
	if _, err = fmt.Fprint(promptWriter, prompt); err != nil {
		return nil, fmt.Errorf("failed to write password prompt: %w", err)
	}
	if password, err = readPassword(fd); err != nil {
		return nil, fmt.Errorf("failed to capture password input: %w", err)
	}
	if _, err = fmt.Fprintln(promptWriter); err != nil {
		return nil, fmt.Errorf("failed to finalize password prompt: %w", err)
	}
	return password, nil
}

// DeriveKey returns a 32-byte key from password using Argon2id.
// The salt, cost parameters, and output length are part of the payload compatibility contract.
// Changing them would make existing encrypted payloads undecryptable with this function.
func DeriveKey(password []byte) []byte {
	salt := []byte("github.com/rbee3u/dpass/internal/dpass.DeriveKey")
	return argon2.IDKey(password, salt, 16, 1*1024*1024, 2, 32)
}
