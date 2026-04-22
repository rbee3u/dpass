// Package aes256 provides CLI commands for AES-256-GCM encryption and decryption.
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

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/helper"
)

// invalidPayloadLengthError reports payload shorter than nonce plus the GCM tag.
type invalidPayloadLengthError struct {
	Got int
	Min int
}

func (e invalidPayloadLengthError) Error() string {
	return fmt.Sprintf("invalid payload length (got %d, must be >= %d)", e.Got, e.Min)
}

// encryptBackend holds dependencies for testing (injectable nonce source).
type encryptBackend struct {
	// nonceReader supplies gcmStandardNonceSize random bytes for each encryption call.
	nonceReader io.Reader
}

// encryptBackendDefault returns a production backend using crypto/rand for nonces.
func encryptBackendDefault() *encryptBackend {
	return &encryptBackend{nonceReader: rand.Reader}
}

// NewCmdEncrypt reads plaintext from stdin and writes hex payload to stdout.
func NewCmdEncrypt() *cobra.Command {
	backend := encryptBackendDefault()
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt stdin with AES-256-GCM and emit a hex payload",
		Example: "  printf 'hello' | dpass encrypt\n" +
			"  cat secret.txt | dpass encrypt",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}

	return cmd
}

// runE reads plaintext and password, then writes hex payload to stdout.
func (b *encryptBackend) runE(_ *cobra.Command, _ []string) error {
	plaintext, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %w", err)
	}

	password, err := helper.ReadPassword("Enter encryption password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	hexPayload, err := b.encrypt(helper.DeriveKey(password), plaintext)
	if err != nil {
		return fmt.Errorf("failed to encrypt: %w", err)
	}

	if _, err := os.Stdout.Write(hexPayload); err != nil {
		return fmt.Errorf("failed to write hex payload: %w", err)
	}

	return nil
}

// encrypt seals plaintext with AES-256-GCM and returns hex payload.
// In this package, payload means nonce||sealed, where sealed already includes the GCM tag.
func (b *encryptBackend) encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM AEAD: %w", err)
	}

	nonceSize, tagSize := aead.NonceSize(), aead.Overhead()

	payload := make([]byte, nonceSize, nonceSize+len(plaintext)+tagSize)
	if _, err := io.ReadFull(b.nonceReader, payload); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}

	payload = aead.Seal(payload, payload, plaintext, nil)
	hexPayload := make([]byte, hex.EncodedLen(len(payload)))
	hex.Encode(hexPayload, payload)

	return hexPayload, nil
}

// decryptBackend parses hex payload produced by encrypt.
type decryptBackend struct{}

// decryptBackendDefault returns a production decrypt command backend.
func decryptBackendDefault() *decryptBackend {
	return &decryptBackend{}
}

// NewCmdDecrypt reads hex payload from stdin and writes plaintext to stdout.
func NewCmdDecrypt() *cobra.Command {
	backend := decryptBackendDefault()
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt an AES-256-GCM hex payload from stdin",
		Example: "  printf '0123abcd' | dpass decrypt\n" +
			"  cat payload.hex | dpass decrypt",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}

	return cmd
}

// runE reads hex payload and password, then writes plaintext to stdout.
func (b *decryptBackend) runE(_ *cobra.Command, _ []string) error {
	hexPayload, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read hex payload: %w", err)
	}

	hexPayload = bytes.TrimSpace(hexPayload)

	password, err := helper.ReadPassword("Enter decryption password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	plaintext, err := b.decrypt(helper.DeriveKey(password), hexPayload)
	if err != nil {
		return err
	}

	if _, err := os.Stdout.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write plaintext: %w", err)
	}

	return nil
}

// decrypt expects hex payload, where payload means nonce||sealed.
// The sealed suffix already includes the GCM tag, so decoded payload must be at least nonce plus tag.
func (b *decryptBackend) decrypt(key, hexPayload []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM AEAD: %w", err)
	}

	nonceSize, tagSize := aead.NonceSize(), aead.Overhead()

	payload := make([]byte, hex.DecodedLen(len(hexPayload)))
	if _, err := hex.Decode(payload, hexPayload); err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	if len(payload) < nonceSize+tagSize {
		return nil, invalidPayloadLengthError{Got: len(payload), Min: nonceSize + tagSize}
	}

	plaintext, err := aead.Open(nil, payload[:nonceSize], payload[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (wrong password or corrupted payload): %w", err)
	}

	return plaintext, nil
}
