package shamir

import (
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/hashicorp/vault/shamir"
	"github.com/spf13/cobra"
)

const (
	outputDefault    = ""
	partsDefault     = 3
	thresholdDefault = 2
	fileMode         = 0o600
)

type splitBackend struct {
	output    string
	parts     int
	threshold int
}

func splitBackendDefault() *splitBackend {
	return &splitBackend{
		output:    outputDefault,
		parts:     partsDefault,
		threshold: thresholdDefault,
	}
}

func RegisterSplit(cmd *cobra.Command) *cobra.Command {
	b := splitBackendDefault()
	cmd.RunE = b.runE

	cmd.Flags().StringVarP(&b.output, "output", "o", outputDefault,
		"prefix of output files, use standard output if empty")
	cmd.Flags().IntVarP(&b.parts, "parts", "n", partsDefault,
		"total number of shares to be split into")
	cmd.Flags().IntVarP(&b.threshold, "threshold", "m", thresholdDefault,
		"minimum number of shares to reconstruct")

	return cmd
}

func (b *splitBackend) runE(_ *cobra.Command, _ []string) error {
	secret, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read secret: %w", err)
	}

	blocks, err := b.split(secret)
	if err != nil {
		return fmt.Errorf("failed to split: %w", err)
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
				"N": strconv.Itoa(b.parts), "M": strconv.Itoa(b.threshold), "I": strconv.Itoa(index),
			},
			Bytes: shares[index],
		}
	}

	return blocks, nil
}

type combineBackend struct{}

func combineBackendDefault() *combineBackend {
	return &combineBackend{}
}

func RegisterCombine(cmd *cobra.Command) *cobra.Command {
	b := combineBackendDefault()
	cmd.RunE = b.runE

	return cmd
}

func (b *combineBackend) runE(_ *cobra.Command, _ []string) error {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("failed to read shares: %w", err)
	}

	var blocks []*pem.Block
	for block, rest := pem.Decode(data); block != nil; {
		blocks = append(blocks, block)
		block, rest = pem.Decode(rest)
	}

	secret, err := b.combine(blocks)
	if err != nil {
		return fmt.Errorf("failed to combine: %w", err)
	}

	if _, err := os.Stdout.Write(secret); err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}

	return nil
}

func (b *combineBackend) combine(blocks []*pem.Block) ([]byte, error) {
	shares := make([][]byte, 0, len(blocks))
	for _, block := range blocks {
		shares = append(shares, block.Bytes)
	}

	secret, err := shamir.Combine(shares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	return secret, nil
}
