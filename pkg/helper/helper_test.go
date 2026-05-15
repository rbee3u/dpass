package helper_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/testx"
)

func TestReadPassword(t *testing.T) {
	t.Run("reads from /dev/tty when stdin is not a terminal", func(t *testing.T) {
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
		var gotFd int
		helper.StubReadPassword(t, func(fd int) ([]byte, error) {
			gotFd = fd
			return []byte("secret"), nil
		})
		wantFd := int(promptWriter.Fd())
		password, err := helper.ReadPassword("Enter password: ")
		require.NoError(t, err)
		testx.EqualSlice(t, []byte("secret"), password)
		require.Equal(t, wantFd, gotFd)
		prompt, err := io.ReadAll(promptReader)
		require.NoError(t, err)
		require.Equal(t, "Enter password: \n", string(prompt))
	})
	t.Run("reads from stdin when stdin is a terminal", func(t *testing.T) {
		promptReader, promptWriter, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, promptReader.Close())
		})
		testx.Stub(t, &os.Stderr, promptWriter)
		helper.StubIsTerminal(t, func(int) bool {
			return true
		})
		var gotFd int
		helper.StubReadPassword(t, func(fd int) ([]byte, error) {
			gotFd = fd
			return []byte("secret"), nil
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.NoError(t, err)
		testx.EqualSlice(t, []byte("secret"), password)
		require.Equal(t, syscall.Stdin, gotFd)
		require.NoError(t, promptWriter.Close())
		prompt, err := io.ReadAll(promptReader)
		require.NoError(t, err)
		require.Equal(t, "Enter password: \n", string(prompt))
	})
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
		testx.Stub(t, &os.Stderr, promptWriter)
		helper.StubIsTerminal(t, func(int) bool {
			return true
		})
		helper.StubReadPassword(t, func(int) ([]byte, error) {
			return []byte("secret"), nil
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to write password prompt")
		require.ErrorIs(t, err, os.ErrClosed)
		require.Nil(t, password)
	})
	t.Run("fails to capture password input", func(t *testing.T) {
		expected := errors.New("read failed")
		promptReader, promptWriter, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, promptReader.Close())
		})
		testx.Stub(t, &os.Stderr, promptWriter)
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
	})
	t.Run("fails to finalize password prompt", func(t *testing.T) {
		promptReader, promptWriter, err := os.Pipe()
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, promptReader.Close())
		})
		testx.Stub(t, &os.Stderr, promptWriter)
		helper.StubIsTerminal(t, func(int) bool {
			return true
		})
		helper.StubReadPassword(t, func(int) ([]byte, error) {
			require.NoError(t, promptWriter.Close())
			return []byte("secret"), nil
		})
		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to finalize password prompt")
		require.ErrorIs(t, err, os.ErrClosed)
		require.Nil(t, password)
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
			key := helper.DeriveKey(tt.password)
			hexKey := hex.EncodeToString(key)
			require.Equal(t, tt.hexKey, hexKey)
		})
	}
}

func TestReadAllLimited(t *testing.T) {
	tests := []struct {
		name   string
		reader io.Reader
		limit  int
		data   []byte
	}{
		{
			name:   "empty input at zero limit",
			reader: bytes.NewReader(nil),
			limit:  0,
			data:   nil,
		},
		{
			name:   "input below limit",
			reader: bytes.NewReader([]byte("hey")),
			limit:  4,
			data:   []byte("hey"),
		},
		{
			name:   "exact limit with no extra byte succeeds",
			reader: bytes.NewReader([]byte("test")),
			limit:  4,
			data:   []byte("test"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := helper.ReadAllLimited(tt.reader, tt.limit)
			require.NoError(t, err)
			testx.EqualSlice(t, tt.data, data)
		})
	}
}

func TestReadAllLimitedErrors(t *testing.T) {
	tests := []struct {
		name       string
		reader     io.Reader
		limit      int
		requireErr func(*testing.T, error)
	}{
		{
			name:   "exact limit with extra byte returns input too long",
			reader: bytes.NewReader([]byte("hello")),
			limit:  4,
			requireErr: func(t *testing.T, err error) {
				var target helper.InputTooLongError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 4, target.Limit)
			},
		},
		{
			name:   "zero limit rejects non-empty input",
			reader: bytes.NewReader([]byte("h")),
			limit:  0,
			requireErr: func(t *testing.T, err error) {
				var target helper.InputTooLongError
				require.ErrorAs(t, err, &target)
				require.Equal(t, 0, target.Limit)
			},
		},
		{
			name:   "read all returns data with trailing error",
			reader: testx.NewReader([]byte("hey"), testx.ErrReadFailure),
			limit:  4,
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
		{
			name: "probe read fails after exact limit",
			reader: io.MultiReader(
				bytes.NewReader([]byte("test")),
				testx.NewReader(nil, testx.ErrReadFailure),
			),
			limit: 4,
			requireErr: func(t *testing.T, err error) {
				require.ErrorIs(t, err, testx.ErrReadFailure)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := helper.ReadAllLimited(tt.reader, tt.limit)
			tt.requireErr(t, err)
			require.Nil(t, data)
		})
	}
}
