package bech32

import "fmt"

// InvalidHrpLengthError reports an HRP whose length is outside [1, 83].
type InvalidHrpLengthError struct {
	// Length is the rejected HRP length.
	Length int
}

func (e InvalidHrpLengthError) Error() string {
	return fmt.Sprintf(
		"bech32: invalid HRP length %d (must be within [%d, %d])",
		e.Length, minHrpLen, maxHrpLen,
	)
}

// InvalidHrpCharError reports an HRP character outside the printable ASCII
// range [33, 126].
type InvalidHrpCharError struct {
	// Offset is the zero-based position of the rejected character in the HRP.
	Offset int
	// Char is the rejected HRP character.
	Char byte
}

func (e InvalidHrpCharError) Error() string {
	return fmt.Sprintf(
		"bech32: invalid HRP character %#U at offset %d (must be within [%#U, %#U])",
		e.Char, e.Offset, minHrpChar, maxHrpChar,
	)
}

// InvalidVerByteError reports a version-prefix byte greater than 31.
type InvalidVerByteError struct {
	// Offset is the zero-based position of the rejected byte in the version
	// prefix.
	Offset int
	// Byte is the rejected version-prefix byte.
	Byte byte
}

func (e InvalidVerByteError) Error() string {
	return fmt.Sprintf(
		"bech32: invalid version byte %d at offset %d (must be <= %d)",
		e.Byte, e.Offset, maxVerByte,
	)
}
