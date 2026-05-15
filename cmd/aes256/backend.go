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

const maxInputBytes = 32 * 1024 * 1024

var (
	readPassword = helper.ReadPassword
	deriveKey    = helper.DeriveKey
)

type encryptBackend struct {
	reader io.Reader
	writer io.Writer
	nonce  io.Reader
}

// NewCmdEncrypt reads plaintext from stdin and writes hex payload to stdout.
func NewCmdEncrypt() *cobra.Command {
	b := &encryptBackend{reader: os.Stdin, writer: os.Stdout, nonce: rand.Reader}
	cmd := &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt a plaintext from stdin with AES-256-GCM and write a hex payload",
		Example: "  printf 'hello' | dpass encrypt\n" +
			"  cat secret.txt | dpass encrypt",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	return cmd
}

func (b *encryptBackend) runE(_ *cobra.Command, _ []string) error {
	plaintext, err := helper.ReadAllLimited(b.reader, maxInputBytes)
	if err != nil {
		return fmt.Errorf("failed to read plaintext: %w", err)
	}
	password, err := readPassword("Enter encryption password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	hexPayload, err := b.encrypt(deriveKey(password), plaintext)
	if err != nil {
		return err
	}
	if _, err := b.writer.Write(hexPayload); err != nil {
		return fmt.Errorf("failed to write hex payload: %w", err)
	}
	return nil
}

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
	if _, err := io.ReadFull(b.nonce, payload); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}
	payload = aead.Seal(payload, payload, plaintext, nil)
	hexPayload := make([]byte, hex.EncodedLen(len(payload)))
	hex.Encode(hexPayload, payload)
	return hexPayload, nil
}

type decryptBackend struct {
	reader io.Reader
	writer io.Writer
}

// NewCmdDecrypt reads hex payload from stdin and writes plaintext to stdout.
func NewCmdDecrypt() *cobra.Command {
	b := &decryptBackend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt an AES-256-GCM hex payload from stdin and write a plaintext",
		Example: "  printf '0123abcd' | dpass decrypt\n" +
			"  cat payload.hex | dpass decrypt",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	return cmd
}

func (b *decryptBackend) runE(_ *cobra.Command, _ []string) error {
	hexPayload, err := helper.ReadAllLimited(b.reader, maxInputBytes)
	if err != nil {
		return fmt.Errorf("failed to read hex payload: %w", err)
	}
	hexPayload = bytes.TrimSpace(hexPayload)
	password, err := readPassword("Enter decryption password: ")
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	plaintext, err := b.decrypt(deriveKey(password), hexPayload)
	if err != nil {
		return err
	}
	if _, err := b.writer.Write(plaintext); err != nil {
		return fmt.Errorf("failed to write plaintext: %w", err)
	}
	return nil
}

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
		return nil, invalidPayloadLengthError{length: len(payload), minLength: nonceSize + tagSize}
	}
	plaintext, err := aead.Open(nil, payload[:nonceSize], payload[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt (wrong password or corrupted payload): %w", err)
	}
	return plaintext, nil
}
