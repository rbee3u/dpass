package base58

import "fmt"

// InvalidAlphabetLengthError reports an alphabet whose byte length is not 58.
type InvalidAlphabetLengthError struct {
	// Length is the rejected alphabet byte length.
	Length int
}

func (e InvalidAlphabetLengthError) Error() string {
	return fmt.Sprintf(
		"base58: invalid alphabet length %d (must be 58)",
		e.Length,
	)
}

// DuplicateAlphabetCharError reports an alphabet byte that appears more than
// once.
type DuplicateAlphabetCharError struct {
	// Offset is the zero-based position of the duplicate character in the alphabet.
	Offset int
	// Char is the duplicate alphabet byte.
	Char byte
}

func (e DuplicateAlphabetCharError) Error() string {
	return fmt.Sprintf(
		"base58: duplicate alphabet character %#U at offset %d",
		e.Char, e.Offset,
	)
}

// InvalidCharError reports an input byte not present in the encoding alphabet.
type InvalidCharError struct {
	// Offset is the zero-based position of the rejected character in the input.
	Offset int
	// Char is the rejected input byte.
	Char byte
}

func (e InvalidCharError) Error() string {
	return fmt.Sprintf(
		"base58: invalid character %#U at offset %d",
		e.Char, e.Offset,
	)
}
