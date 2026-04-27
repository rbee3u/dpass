package helper_test

import (
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/helper"
)

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

func TestReadPassword(t *testing.T) {
	promptReader, promptWriter, err := os.Pipe()
	require.NoError(t, err)

	wantFD := int(promptWriter.Fd())
	var gotFD int
	helper.StubPasswordDependenciesForTest(
		t,
		func(int) bool {
			return false
		},
		func(fd int) ([]byte, error) {
			gotFD = fd
			return []byte("secret"), nil
		},
		func() (*os.File, error) {
			return promptWriter, nil
		},
	)

	password, err := helper.ReadPassword("Enter password: ")
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), password)
	require.Equal(t, wantFD, gotFD)

	prompt, err := io.ReadAll(promptReader)
	require.NoError(t, err)
	require.Equal(t, "Enter password: \n", string(prompt))

	require.NoError(t, promptReader.Close())
}

func TestReadPasswordErrors(t *testing.T) {
	t.Run("fails to open terminal", func(t *testing.T) {
		expected := errors.New("no tty")

		helper.StubPasswordDependenciesForTest(
			t,
			func(int) bool {
				return false
			},
			nil,
			func() (*os.File, error) {
				return nil, expected
			},
		)

		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to open terminal")
		require.ErrorIs(t, err, expected)
		require.Nil(t, password)
	})

	t.Run("fails to read password", func(t *testing.T) {
		expected := errors.New("read failed")

		stderrReader, stderrWriter, err := os.Pipe()
		require.NoError(t, err)
		oldStderr := os.Stderr
		os.Stderr = stderrWriter
		t.Cleanup(func() {
			os.Stderr = oldStderr
		})

		helper.StubPasswordDependenciesForTest(
			t,
			func(int) bool {
				return true
			},
			func(int) ([]byte, error) {
				return nil, expected
			},
			nil,
		)

		password, err := helper.ReadPassword("Enter password: ")
		require.Error(t, err)
		require.ErrorContains(t, err, "failed to read password")
		require.ErrorIs(t, err, expected)
		require.Nil(t, password)

		require.NoError(t, stderrWriter.Close())
		_, err = io.ReadAll(stderrReader)
		require.NoError(t, err)
		require.NoError(t, stderrReader.Close())
	})
}

func TestReadMnemonic(t *testing.T) {
	stdinReader, stdinWriter, err := os.Pipe()
	require.NoError(t, err)
	oldStdin := os.Stdin
	os.Stdin = stdinReader
	t.Cleanup(func() {
		os.Stdin = oldStdin
	})

	_, err = stdinWriter.WriteString("  abandon\tabandon\nabout  \n")
	require.NoError(t, err)
	require.NoError(t, stdinWriter.Close())

	mnemonic, err := helper.ReadMnemonic()
	require.NoError(t, err)
	require.Equal(t, "abandon abandon about", mnemonic)

	require.NoError(t, stdinReader.Close())
}

func TestReadMnemonicErrors(t *testing.T) {
	stdinReader, stdinWriter, err := os.Pipe()
	require.NoError(t, err)
	require.NoError(t, stdinReader.Close())
	require.NoError(t, stdinWriter.Close())

	oldStdin := os.Stdin
	os.Stdin = stdinReader
	t.Cleanup(func() {
		os.Stdin = oldStdin
	})

	mnemonic, err := helper.ReadMnemonic()
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to read mnemonic")
	require.ErrorIs(t, err, os.ErrClosed)
	require.Empty(t, mnemonic)
}
