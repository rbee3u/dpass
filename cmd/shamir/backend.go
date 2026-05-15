// Package shamir provides CLI commands for splitting and combining Shamir shares.
package shamir

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/rbee3u/dpass/pkg/helper"
	"github.com/rbee3u/dpass/pkg/shamir"
)

const maxInputBytes = 32 * 1024 * 1024

type splitBackend struct {
	output    string
	parts     int
	threshold int
	reader    io.Reader
	writer    io.Writer
}

// NewCmdSplit reads a secret from stdin and writes PEM-encoded shares to files or stdout.
func NewCmdSplit() *cobra.Command {
	sb := &splitBackend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split stdin into PEM-encoded Shamir shares",
		Example: "  printf 'correct horse battery staple' | dpass split -o share -n 5 -m 3\n" +
			"  printf 'correct horse battery staple' | dpass split -n 5 -m 3 >shares.pem",
		Args: cobra.NoArgs,
		RunE: sb.runE,
	}
	cmd.Flags().StringVarP(&sb.output, "output", "o", "",
		"output file prefix; write to stdout when empty")
	cmd.Flags().IntVarP(&sb.parts, "parts", "n", 3,
		"total number of shares to generate")
	cmd.Flags().IntVarP(&sb.threshold, "threshold", "m", 2,
		"minimum number of shares required to reconstruct the secret")
	return cmd
}

func (b *splitBackend) runE(_ *cobra.Command, _ []string) error {
	secret, err := helper.ReadAllLimited(b.reader, maxInputBytes)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}
	shares, err := shamir.Split(secret, b.parts, b.threshold)
	if err != nil {
		return fmt.Errorf("failed to split secret: %w", err)
	}
	for index, share := range shares {
		block := &pem.Block{
			Type: "SHAMIR",
			Headers: map[string]string{
				"N": strconv.Itoa(b.parts),
				"M": strconv.Itoa(b.threshold),
				"I": strconv.Itoa(index),
			},
			Bytes: share,
		}
		if len(b.output) == 0 {
			err = pem.Encode(b.writer, block)
		} else {
			name := fmt.Sprintf("%s-%v-%v-%v.txt", b.output, b.parts, b.threshold, index)
			err = os.WriteFile(name, pem.EncodeToMemory(block), 0o600)
		}
		if err != nil {
			return fmt.Errorf("failed to write share %d: %w", index, err)
		}
	}
	return nil
}

type combineBackend struct {
	reader io.Reader
	writer io.Writer
}

// NewCmdCombine reads PEM shares from stdin and writes the recovered secret to stdout.
func NewCmdCombine() *cobra.Command {
	cb := &combineBackend{reader: os.Stdin, writer: os.Stdout}
	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine PEM-encoded Shamir shares from stdin",
		Example: "  cat share-5-3-0.txt share-5-3-1.txt share-5-3-2.txt | dpass combine\n" +
			"  cat shares.pem | dpass combine",
		Args: cobra.NoArgs,
		RunE: cb.runE,
	}
	return cmd
}

func (b *combineBackend) runE(_ *cobra.Command, _ []string) error {
	data, err := helper.ReadAllLimited(b.reader, maxInputBytes)
	if err != nil {
		return fmt.Errorf("failed to read shares: %w", err)
	}
	data = bytes.TrimSpace(data)
	var blocks []*pem.Block
	for len(data) != 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			return errMalformedPEMInput
		}
		blocks = append(blocks, block)
		data = bytes.TrimSpace(rest)
	}
	if len(blocks) == 0 {
		return errNoSharesProvided
	}
	parts, threshold, index, err := validateBlock(blocks[0], 0)
	if err != nil {
		return err
	}
	indices := map[int]int{index: 0}
	for i := 1; i < len(blocks); i++ {
		currParts, currThreshold, currIndex, err := validateBlock(blocks[i], i)
		if err != nil {
			return err
		}
		if currParts != parts {
			return inconsistentHeaderError{pos: i, key: "N", got: currParts, want: parts}
		}
		if currThreshold != threshold {
			return inconsistentHeaderError{pos: i, key: "M", got: currThreshold, want: threshold}
		}
		if prevPos, exists := indices[currIndex]; exists {
			return duplicateHeaderError{pos: i, key: "I", value: currIndex, prevPos: prevPos}
		}
		indices[currIndex] = i
	}
	shares := make([][]byte, 0, len(blocks))
	for _, block := range blocks {
		shares = append(shares, block.Bytes)
	}
	if len(shares) < threshold {
		return insufficientSharesError{got: len(shares), min: threshold}
	}
	secret, err := shamir.Combine(shares)
	if err != nil {
		return fmt.Errorf("failed to combine shares: %w", err)
	}
	if _, err := b.writer.Write(secret); err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}
	return nil
}

func validateBlock(block *pem.Block, pos int) (int, int, int, error) {
	if block.Type != "SHAMIR" {
		return 0, 0, 0, unexpectedBlockTypeError{pos: pos, got: block.Type, want: "SHAMIR"}
	}
	parts, err := extractHeader(block, pos, "N")
	if err != nil {
		return 0, 0, 0, err
	}
	threshold, err := extractHeader(block, pos, "M")
	if err != nil {
		return 0, 0, 0, err
	}
	index, err := extractHeader(block, pos, "I")
	if err != nil {
		return 0, 0, 0, err
	}
	if !(shamir.MinShares <= threshold && threshold <= parts && parts <= shamir.MaxShares &&
		0 <= index && index < parts) {
		return 0, 0, 0, invalidHeaderError{pos: pos, parts: parts, threshold: threshold, index: index}
	}
	return parts, threshold, index, nil
}

func extractHeader(block *pem.Block, pos int, key string) (int, error) {
	value := block.Headers[key]
	if len(value) == 0 {
		return 0, missingHeaderError{pos: pos, key: key}
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, malformedHeaderError{pos: pos, key: key, value: value, err: err}
	}
	return number, nil
}
