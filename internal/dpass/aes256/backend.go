package aes256

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/rbee3u/dpass/internal/dpass"
	"github.com/spf13/cobra"
)

const gcmStandardNonceSize = 12

type encryptBackend struct {
	nonceReader io.Reader
}

func encryptBackendDefault() *encryptBackend {
	return &encryptBackend{nonceReader: rand.Reader}
}

func RegisterEncrypt(cmd *cobra.Command) *cobra.Command {
	b := encryptBackendDefault()
	cmd.RunE = b.runE

	return cmd
}

func (b *encryptBackend) runE(_ *cobra.Command, _ []string) error {
	plaintext, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %w", err)
	}

	password, err := dpass.ReadPassword("Password For Encrypt:")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	key := dpass.DeriveKey(password)

	encodedNonceAndCiphertext, err := b.encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	if _, err := os.Stdout.Write(encodedNonceAndCiphertext); err != nil {
		return fmt.Errorf("failed to write encoded nonce and ciphertext: %w", err)
	}

	return nil
}

func (b *encryptBackend) encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to new block: %w", err)
	}

	aead, err := cipher.NewGCMWithNonceSize(block, gcmStandardNonceSize)
	if err != nil {
		return nil, fmt.Errorf("failed to new aead: %w", err)
	}

	nonce := make([]byte, gcmStandardNonceSize)
	if _, err := io.ReadFull(b.nonceReader, nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	nonceAndCiphertext := make([]byte, gcmStandardNonceSize+len(ciphertext))
	copy(nonceAndCiphertext[:gcmStandardNonceSize], nonce)
	copy(nonceAndCiphertext[gcmStandardNonceSize:], ciphertext)

	encodedNonceAndCiphertext := make([]byte, hex.EncodedLen(len(nonceAndCiphertext)))
	hex.Encode(encodedNonceAndCiphertext, nonceAndCiphertext)

	return encodedNonceAndCiphertext, nil
}

type decryptBackend struct{}

func decryptBackendDefault() *decryptBackend {
	return &decryptBackend{}
}

func RegisterDecrypt(cmd *cobra.Command) *cobra.Command {
	b := decryptBackendDefault()
	cmd.RunE = b.runE

	return cmd
}

func (b *decryptBackend) runE(_ *cobra.Command, _ []string) error {
	encodedNonceAndCiphertext, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read encoded nonce and ciphertext: %w", err)
	}

	encodedNonceAndCiphertext = bytes.TrimSpace(encodedNonceAndCiphertext)

	password, err := dpass.ReadPassword("Password For Decrypt:")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	key := dpass.DeriveKey(password)

	plaintext, err := b.decrypt(key, encodedNonceAndCiphertext)
	if err != nil {
		return fmt.Errorf("failed to decrypt: %w", err)
	}

	if _, err := os.Stdout.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write plaintext: %w", err)
	}

	return nil
}

func (b *decryptBackend) decrypt(key, encodedNonceAndCiphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to new block: %w", err)
	}

	aead, err := cipher.NewGCMWithNonceSize(block, gcmStandardNonceSize)
	if err != nil {
		return nil, fmt.Errorf("failed to new aead: %w", err)
	}

	nonceAndCiphertext := make([]byte, hex.DecodedLen(len(encodedNonceAndCiphertext)))
	if _, err := hex.Decode(nonceAndCiphertext, encodedNonceAndCiphertext); err != nil {
		return nil, fmt.Errorf("failed to decode nonce and ciphertext: %w", err)
	}

	nonce := nonceAndCiphertext[:gcmStandardNonceSize]
	ciphertext := nonceAndCiphertext[gcmStandardNonceSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
