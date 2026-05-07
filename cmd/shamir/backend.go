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

	"github.com/rbee3u/dpass/pkg/shamir"
)

const (
	// outputDefault writes shares to stdout unless a prefix is provided.
	outputDefault = ""
	// partsDefault generates three shares by default.
	partsDefault = 3
	// thresholdDefault requires any two shares to reconstruct the secret.
	thresholdDefault = 2
)

// splitBackend configures share count, threshold, and optional output file prefix.
type splitBackend struct {
	// output is the optional filename prefix; empty means stdout.
	output string
	// parts is the total number of shares to generate.
	parts int
	// threshold is the minimum share count required to reconstruct the secret.
	threshold int
}

// splitBackendDefault is a 2-of-3 style demo default; callers override via flags.
func splitBackendDefault() *splitBackend {
	return &splitBackend{
		output:    outputDefault,
		parts:     partsDefault,
		threshold: thresholdDefault,
	}
}

// NewCmdSplit reads a secret from stdin and writes PEM-encoded shares to files or stdout.
func NewCmdSplit() *cobra.Command {
	b := splitBackendDefault()
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split stdin into PEM-encoded Shamir shares",
		Example: "  printf 'correct horse battery staple' | dpass split -o share -n 5 -m 3\n" +
			"  printf 'correct horse battery staple' | dpass split -n 5 -m 3 >shares.pem",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	cmd.Flags().StringVarP(&b.output, "output", "o", outputDefault,
		"output file prefix; write to stdout when empty")
	cmd.Flags().IntVarP(&b.parts, "parts", "n", partsDefault,
		"total number of shares to generate")
	cmd.Flags().IntVarP(&b.threshold, "threshold", "m", thresholdDefault,
		"minimum number of shares required to reconstruct the secret")
	return cmd
}

// runE splits stdin into PEM shares, writing either concatenated stdout or prefixed files.
func (b *splitBackend) runE(_ *cobra.Command, _ []string) error {
	secret, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}
	blocks, err := b.split(secret)
	if err != nil {
		return err
	}
	for index := range blocks {
		if len(b.output) == 0 {
			err = pem.Encode(os.Stdout, blocks[index])
		} else {
			name := fmt.Sprintf("%s-%v-%v-%v.txt", b.output, b.parts, b.threshold, index)
			err = os.WriteFile(name, pem.EncodeToMemory(blocks[index]), 0o600)
		}
		if err != nil {
			return fmt.Errorf("failed to write share %d: %w", index, err)
		}
	}
	return nil
}

// split wraps shamir.Split and attaches N/M/I metadata headers for combine.
func (b *splitBackend) split(secret []byte) ([]*pem.Block, error) {
	shares, err := shamir.Split(secret, b.parts, b.threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to split secret: %w", err)
	}
	blocks := make([]*pem.Block, len(shares))
	for index := range shares {
		blocks[index] = &pem.Block{
			Type: "SHAMIR",
			Headers: map[string]string{
				"N": strconv.Itoa(b.parts),
				"M": strconv.Itoa(b.threshold),
				"I": strconv.Itoa(index),
			},
			Bytes: shares[index],
		}
	}
	return blocks, nil
}

// combineBackend reconstructs a secret from concatenated PEM shares on stdin.
type combineBackend struct{}

// combineBackendDefault returns a production combine command backend.
func combineBackendDefault() *combineBackend {
	return &combineBackend{}
}

// NewCmdCombine reads PEM shares from stdin and writes the recovered secret to stdout.
func NewCmdCombine() *cobra.Command {
	b := combineBackendDefault()
	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine PEM-encoded Shamir shares from stdin",
		Example: "  cat share-5-3-0.txt share-5-3-1.txt share-5-3-2.txt | dpass combine\n" +
			"  cat shares.pem | dpass combine",
		Args: cobra.NoArgs,
		RunE: b.runE,
	}
	return cmd
}

// runE decodes PEM shares from stdin and prints the recovered secret.
func (b *combineBackend) runE(_ *cobra.Command, _ []string) error {
	data, err := io.ReadAll(os.Stdin)
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
	secret, err := b.combine(blocks)
	if err != nil {
		return err
	}
	if _, err := os.Stdout.Write(secret); err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}
	return nil
}

// combine validates per-share metadata, enforces cross-share header
// consistency, and checks the encoded threshold before delegating share
// encoding validation to shamir.Combine.
func (b *combineBackend) combine(blocks []*pem.Block) ([]byte, error) {
	if len(blocks) == 0 {
		return nil, errNoSharesProvided
	}
	parts, threshold, index, err := validateBlock(blocks[0], 0)
	if err != nil {
		return nil, err
	}
	indices := map[int]int{index: 0}
	for i := 1; i < len(blocks); i++ {
		currParts, currThreshold, currIndex, err := validateBlock(blocks[i], i)
		if err != nil {
			return nil, err
		}
		if currParts != parts {
			return nil, inconsistentHeaderError{Pos: i, Key: "N", Got: currParts, Want: parts}
		}
		if currThreshold != threshold {
			return nil, inconsistentHeaderError{Pos: i, Key: "M", Got: currThreshold, Want: threshold}
		}
		if prevPos, exists := indices[currIndex]; exists {
			return nil, duplicateHeaderError{Pos: i, Key: "I", Value: currIndex, PrevPos: prevPos}
		}
		indices[currIndex] = i
	}
	shares := make([][]byte, 0, len(blocks))
	for _, block := range blocks {
		shares = append(shares, block.Bytes)
	}
	if len(shares) < threshold {
		return nil, insufficientSharesError{Got: len(shares), Need: threshold}
	}
	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}
	return secret, nil
}

// validateBlock validates a single PEM block's headers and extracts their values.
func validateBlock(block *pem.Block, pos int) (int, int, int, error) {
	if block.Type != "SHAMIR" {
		return 0, 0, 0, unexpectedBlockTypeError{Pos: pos, Got: block.Type, Want: "SHAMIR"}
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
		return 0, 0, 0, invalidHeaderError{Pos: pos, Parts: parts, Threshold: threshold, Index: index}
	}
	return parts, threshold, index, nil
}

// extractHeader parses an integer PEM header value for the share at the given position.
func extractHeader(block *pem.Block, pos int, key string) (int, error) {
	value := block.Headers[key]
	if len(value) == 0 {
		return 0, missingHeaderError{Pos: pos, Key: key}
	}
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, malformedHeaderError{Pos: pos, Key: key, Value: value, Err: err}
	}
	return number, nil
}
