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

// CLI defaults for splitting shares and the file mode used for persisted output.
const (
	// outputDefault writes shares to stdout unless a prefix is provided.
	outputDefault = ""
	// partsDefault generates three shares by default.
	partsDefault = 3
	// thresholdDefault requires any two shares to reconstruct the secret.
	thresholdDefault = 2
	// fileMode restricts PEM share files to the owner (split output only).
	fileMode = 0o600
	// shareType identifies PEM blocks produced by this command.
	shareType = "SHAMIR"
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
	backend := splitBackendDefault()
	cmd := &cobra.Command{
		Use:   "split",
		Short: "Split stdin into PEM-encoded Shamir shares",
		Example: "  printf 'correct horse battery staple' | dpass split\n" +
			"  printf 'correct horse battery staple' | dpass split --parts 5 --threshold 3 --output share",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}
	cmd.Flags().StringVarP(&backend.output, "output", "o", outputDefault,
		"output file prefix; write to stdout when empty")
	cmd.Flags().IntVarP(&backend.parts, "parts", "n", partsDefault,
		"total number of shares to generate")
	cmd.Flags().IntVarP(&backend.threshold, "threshold", "m", thresholdDefault,
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
			path := fmt.Sprintf("%s-%v-%v-%v.txt", b.output, b.parts, b.threshold, index)
			err = os.WriteFile(path, pem.EncodeToMemory(blocks[index]), fileMode)
		}

		if err != nil {
			return fmt.Errorf("failed to write block: %w", err)
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
			Type: shareType,
			Headers: map[string]string{
				"N": strconv.Itoa(b.parts), "M": strconv.Itoa(b.threshold), "I": strconv.Itoa(index),
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
	backend := combineBackendDefault()
	cmd := &cobra.Command{
		Use:   "combine",
		Short: "Combine PEM-encoded Shamir shares from stdin",
		Example: "  cat share-3-2-0.txt share-3-2-1.txt | dpass combine\n" +
			"  cat shares.pem | dpass combine",
		Args: cobra.NoArgs,
		RunE: backend.runE,
	}

	return cmd
}

// runE decodes PEM shares from stdin and prints the recovered secret.
func (b *combineBackend) runE(_ *cobra.Command, _ []string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read shares: %w", err)
	}

	blocks, err := decodePEMBlocks(data)
	if err != nil {
		return fmt.Errorf("failed to decode shares: %w", err)
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

// combine enforces threshold M from headers before delegating to shamir.Combine.
func (b *combineBackend) combine(blocks []*pem.Block) ([]byte, error) {
	metadata, err := combineMetadata(blocks)
	if err != nil {
		return nil, err
	}

	shares := make([][]byte, 0, len(blocks))
	for _, block := range blocks {
		shares = append(shares, block.Bytes)
	}

	if len(shares) < metadata.threshold {
		return nil, insufficientSharesError{Got: len(shares), Need: metadata.threshold}
	}

	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	return secret, nil
}

// combineMetadata returns validated threshold/parts metadata shared by all blocks.
func combineMetadata(blocks []*pem.Block) (shareMetadata, error) {
	if len(blocks) == 0 {
		return shareMetadata{}, errNoSharesProvided
	}

	metadata, err := decodeShareBlockMetadata(blocks[0], 0)
	if err != nil {
		return shareMetadata{}, err
	}

	if len(blocks) > metadata.parts {
		return shareMetadata{}, tooManySharesError{Got: len(blocks), Max: metadata.parts}
	}

	indices := map[int]int{metadata.index: 0}

	for i := 1; i < len(blocks); i++ {
		current, err := decodeShareBlockMetadata(blocks[i], i)
		if err != nil {
			return shareMetadata{}, err
		}

		if current.threshold != metadata.threshold {
			return shareMetadata{}, inconsistentHeaderError{
				Position: i, Key: "M", Got: current.threshold, Want: metadata.threshold,
			}
		}

		if current.parts != metadata.parts {
			return shareMetadata{}, inconsistentHeaderError{
				Position: i, Key: "N", Got: current.parts, Want: metadata.parts,
			}
		}

		if previous, exists := indices[current.index]; exists {
			return shareMetadata{}, duplicateHeaderValueError{
				Position: i, Previous: previous, Key: "I", Value: current.index,
			}
		}

		indices[current.index] = i
	}

	return metadata, nil
}

// shareMetadata stores the validated split parameters encoded in each PEM block.
type shareMetadata struct {
	// threshold is the minimum share count required to reconstruct the secret.
	threshold int
	// parts is the total number of shares originally generated.
	parts int
	// index is the zero-based share index encoded in header I.
	index int
}

// decodeShareBlockMetadata validates a single PEM block and returns its metadata.
func decodeShareBlockMetadata(block *pem.Block, position int) (shareMetadata, error) {
	if block.Type != shareType {
		return shareMetadata{}, unexpectedBlockTypeError{
			Position: position, Got: block.Type, Want: shareType,
		}
	}

	threshold, err := pemHeaderInt(block, position, "M")
	if err != nil {
		return shareMetadata{}, err
	}

	if threshold < shamir.MinShares || threshold > shamir.MaxShares {
		return shareMetadata{}, invalidHeaderError{
			Position: position, Key: "M", Value: threshold,
			Detail: fmt.Sprintf("must be within [%d, %d]", shamir.MinShares, shamir.MaxShares),
		}
	}

	parts, err := pemHeaderInt(block, position, "N")
	if err != nil {
		return shareMetadata{}, err
	}

	if parts < threshold || parts > shamir.MaxShares {
		return shareMetadata{}, invalidHeaderError{
			Position: position, Key: "N", Value: parts,
			Detail: fmt.Sprintf("must be within [%d, %d]", threshold, shamir.MaxShares),
		}
	}

	index, err := pemHeaderInt(block, position, "I")
	if err != nil {
		return shareMetadata{}, err
	}

	if index < 0 || index >= parts {
		return shareMetadata{}, invalidHeaderError{
			Position: position, Key: "I", Value: index,
			Detail: fmt.Sprintf("must be within [0, %d]", parts-1),
		}
	}

	if len(block.Bytes) < shamir.MinShareLength {
		return shareMetadata{}, emptyShareBodyError{Position: position}
	}

	return shareMetadata{threshold: threshold, parts: parts, index: index}, nil
}

// decodePEMBlocks decodes concatenated PEM blocks and rejects trailing garbage.
func decodePEMBlocks(data []byte) ([]*pem.Block, error) {
	var blocks []*pem.Block

	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			if len(bytes.TrimSpace(data)) == 0 {
				return blocks, nil
			}

			return nil, errMalformedPEMInput
		}

		blocks = append(blocks, block)
		data = rest
	}

	return blocks, nil
}

// pemHeaderInt parses an integer PEM header value for the share at the given position.
func pemHeaderInt(block *pem.Block, position int, key string) (int, error) {
	value, ok := block.Headers[key]
	if !ok {
		return 0, missingHeaderError{Position: position, Key: key}
	}

	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, unparsableHeaderError{Position: position, Key: key, Value: value, Err: err}
	}

	return number, nil
}
