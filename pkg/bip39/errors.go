package bip39

import "fmt"

// InvalidWordCountError reports a word count outside the supported BIP-39
// sizes: 12, 15, 18, 21, and 24.
type InvalidWordCountError struct {
	// WordCount is the rejected mnemonic word count.
	WordCount int
}

func (e InvalidWordCountError) Error() string {
	return fmt.Sprintf(
		"bip39: invalid word count %d (must be 12, 15, 18, 21, or 24)",
		e.WordCount,
	)
}

// WordNotFoundError reports a mnemonic word missing from the English wordlist.
type WordNotFoundError struct {
	// Word is the mnemonic token missing from the English wordlist.
	Word []byte
}

func (e WordNotFoundError) Error() string {
	return fmt.Sprintf(
		"bip39: mnemonic word %q is not in the English wordlist",
		e.Word,
	)
}

// ChecksumMismatchError reports that a mnemonic checksum does not match the
// checksum recomputed from the decoded entropy.
type ChecksumMismatchError struct {
	// Checksum is the checksum value encoded in the mnemonic.
	Checksum uint32
	// WantChecksum is the checksum recomputed from the decoded entropy.
	WantChecksum uint32
}

func (e ChecksumMismatchError) Error() string {
	return fmt.Sprintf(
		"bip39: mnemonic checksum mismatch (got %d, want %d)",
		e.Checksum, e.WantChecksum,
	)
}
