package helper_test

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/helper"
)

func TestReadPassword(t *testing.T) {
	tests := []struct {
		name       string
		isTerminal bool
	}{
		{
			name:       "stdin is not terminal",
			isTerminal: false,
		},
		{
			name:       "stdin is terminal",
			isTerminal: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			promptReader, promptWriter, err := os.Pipe()
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, promptReader.Close())
			})
			helper.StubIsTerminal(t, func(int) bool {
				return tt.isTerminal
			})
			var wantFd int
			var openTerminalCalled bool
			if !tt.isTerminal {
				wantFd = int(promptWriter.Fd())
				helper.StubOpenTerminal(t, func() (*os.File, error) {
					openTerminalCalled = true
					return promptWriter, nil
				})
			} else {
				wantFd = syscall.Stdin
				helper.Stub(t, &os.Stderr, promptWriter)
				helper.StubOpenTerminal(t, func() (*os.File, error) {
					openTerminalCalled = true
					return nil, errors.New("unexpected terminal open")
				})
			}
			var gotFd int
			helper.StubReadPassword(t, func(fd int) ([]byte, error) {
				gotFd = fd
				return []byte("secret"), nil
			})
			password, err := helper.ReadPassword("Enter password: ")
			require.NoError(t, err)
			require.Equal(t, []byte("secret"), password)
			require.Equal(t, wantFd, gotFd)
			require.Equal(t, !tt.isTerminal, openTerminalCalled)
			if tt.isTerminal {
				require.NoError(t, promptWriter.Close())
			}
			prompt, err := io.ReadAll(promptReader)
			require.NoError(t, err)
			require.Equal(t, "Enter password: \n", string(prompt))
		})
	}
}

func TestReadPasswordErrors(t *testing.T) {
	t.Run("fails to open terminal", func(t *testing.T) {
		expected := errors.New("no tty")
		helper.StubIsTerminal(t, func(int) bool {
			return false
		})
		helper.StubOpenTerminal(t, func() (*os.File, error) {
			return nil, expected
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to open terminal for password input")
		require.ErrorIs(t, err, expected)
		require.Nil(t, password)
	})
	t.Run("fails to write password prompt", func(t *testing.T) {
		_, promptWriter, err := os.Pipe()
		require.NoError(t, err)
		require.NoError(t, promptWriter.Close())
		helper.Stub(t, &os.Stderr, promptWriter)
		var readPasswordCalled bool
		helper.StubIsTerminal(t, func(int) bool {
			return true
		})
		helper.StubReadPassword(t, func(int) ([]byte, error) {
			readPasswordCalled = true
			return []byte("secret"), nil
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to write password prompt")
		require.ErrorIs(t, err, os.ErrClosed)
		require.Nil(t, password)
		require.False(t, readPasswordCalled)
	})
	t.Run("fails to capture password input", func(t *testing.T) {
		expected := errors.New("read failed")
		promptReader, promptWriter, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, promptReader.Close())
		})
		helper.Stub(t, &os.Stderr, promptWriter)
		helper.StubIsTerminal(t, func(int) bool {
			return true
		})
		helper.StubReadPassword(t, func(int) ([]byte, error) {
			return nil, expected
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to capture password input")
		require.ErrorIs(t, err, expected)
		require.Nil(t, password)
		require.NoError(t, promptWriter.Close())
		_, err = io.ReadAll(promptReader)
		require.NoError(t, err)
	})
	t.Run("fails to finalize password prompt", func(t *testing.T) {
		promptReader, promptWriter, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, promptReader.Close())
		})
		helper.Stub(t, &os.Stderr, promptWriter)
		var readPasswordCalled bool
		helper.StubIsTerminal(t, func(int) bool {
			return true
		})
		helper.StubReadPassword(t, func(int) ([]byte, error) {
			readPasswordCalled = true
			require.NoError(t, promptWriter.Close())
			return []byte("secret"), nil
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to finalize password prompt")
		require.ErrorIs(t, err, os.ErrClosed)
		require.Nil(t, password)
		require.True(t, readPasswordCalled)
	})
	t.Run("fails to close terminal", func(t *testing.T) {
		expected := errors.New("close failed")
		promptReader, promptWriter, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, promptReader.Close())
		})
		helper.StubIsTerminal(t, func(int) bool {
			return false
		})
		helper.StubOpenTerminal(t, func() (*os.File, error) {
			return promptWriter, nil
		})
		helper.StubCloseTerminal(t, func(terminal *os.File) error {
			require.NoError(t, terminal.Close())
			return expected
		})
		helper.StubReadPassword(t, func(int) ([]byte, error) {
			return []byte("secret"), nil
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to close terminal used for password input")
		require.ErrorIs(t, err, expected)
		require.Nil(t, password)
		prompt, err := io.ReadAll(promptReader)
		require.NoError(t, err)
		require.Equal(t, "Enter password: \n", string(prompt))
	})
}

func TestDeriveKey(t *testing.T) {
	tests := []struct {
		name     string
		password []byte
		hexKey   string
	}{
		{
			name:     "short password",
			password: []byte("_Short"),
			hexKey:   "66d93505bb87124fda05ac4ad3105e7b1cab52be2eb020c859a33f4769ad51c3",
		},
		{
			name:     "long password",
			password: []byte("_LongLongLongLongLongLongLongLongLongLongLongLongLongLongLongLong"),
			hexKey:   "73f32f797252f2756f4342205ff8944efa4cf62a4ce3b9a10e8a13bcdc3af1fa",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.hexKey, hex.EncodeToString(helper.DeriveKey(tt.password)))
		})
	}
}
