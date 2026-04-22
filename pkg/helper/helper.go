// Package helper provides shared CLI helpers for passwords, mnemonics, and keys.
package helper

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

// ReadPassword prints prompt, reads a line without echo when possible, then a trailing newline.
// When stdin is not a TTY, it reads from /dev/tty so pipes still work for ciphertext on stdin.
func ReadPassword(prompt string) (password []byte, err error) {
	promptWriter := io.Writer(os.Stderr)

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
		promptWriter = terminal
	}

	_, _ = fmt.Fprint(promptWriter, prompt)

	if password, err = term.ReadPassword(fileDescriptor); err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	_, _ = fmt.Fprintln(promptWriter)

	return password, nil
}

// DeriveKey returns a 32-byte key from password using Argon2id key derivation function.
// The salt, cost parameters and length of key are hardcoded, don't modify them!!!!!
func DeriveKey(password []byte) []byte {
	salt := []byte("github.com/rbee3u/dpass/internal/dpass.DeriveKey")

	return argon2.IDKey(password, salt, 16, 1*1024*1024, 2, 32)
}

// ReadMnemonic reads stdin and returns whitespace-normalized BIP-39 words (single spaces).
func ReadMnemonic() (string, error) {
	mnemonic, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("failed to read mnemonic: %w", err)
	}

	return strings.Join(strings.Fields(string(mnemonic)), " "), nil
}
