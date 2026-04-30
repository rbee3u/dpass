package shamir

import (
	"errors"
	"fmt"
)

// Sentinel errors without context parameters.
var (
	// errNoSharesProvided reports that combine received no PEM blocks.
	errNoSharesProvided = errors.New("no shares provided")
	// errMalformedPEMInput reports trailing non-PEM data after decoding share blocks.
	errMalformedPEMInput = errors.New("malformed PEM input")
)

// missingHeaderError reports a required PEM header key absent from a share block.
type missingHeaderError struct {
	Position int
	Key      string
}

func (e missingHeaderError) Error() string {
	return fmt.Sprintf("share %d: missing %s header", e.Position, e.Key)
}

// unparsableHeaderError reports a PEM header value that failed to parse.
type unparsableHeaderError struct {
	Position int
	Key      string
	Value    string
	Err      error
}

func (e unparsableHeaderError) Error() string {
	return fmt.Sprintf("share %d: invalid %s header (got %q): %v", e.Position, e.Key, e.Value, e.Err)
}

func (e unparsableHeaderError) Unwrap() error {
	return e.Err
}

// invalidHeaderError reports a PEM header value outside the supported range.
type invalidHeaderError struct {
	Position int
	Key      string
	Value    int
	Detail   string
}

func (e invalidHeaderError) Error() string {
	return fmt.Sprintf("share %d: invalid %s header %d (%s)", e.Position, e.Key, e.Value, e.Detail)
}

// inconsistentHeaderError reports that share headers disagree on a field value.
type inconsistentHeaderError struct {
	Position int
	Key      string
	Got      int
	Want     int
}

func (e inconsistentHeaderError) Error() string {
	return fmt.Sprintf("share %d: inconsistent %s header (got %d, want %d)", e.Position, e.Key, e.Got, e.Want)
}

// duplicateHeaderValueError reports two shares claiming the same header value.
type duplicateHeaderValueError struct {
	Position int
	Previous int
	Key      string
	Value    int
}

func (e duplicateHeaderValueError) Error() string {
	return fmt.Sprintf("share %d: duplicate %s header %d (already used by share %d)", e.Position, e.Key, e.Value, e.Previous)
}

// tooManySharesError reports more shares than the declared N header.
type tooManySharesError struct {
	Got int
	Max int
}

func (e tooManySharesError) Error() string {
	return fmt.Sprintf("too many shares (got %d, must be <= %d)", e.Got, e.Max)
}

// unexpectedBlockTypeError reports a PEM block type other than the expected share type.
type unexpectedBlockTypeError struct {
	Position int
	Got      string
	Want     string
}

func (e unexpectedBlockTypeError) Error() string {
	return fmt.Sprintf("share %d: unexpected block type (got %q, want %q)", e.Position, e.Got, e.Want)
}

// emptyShareBodyError reports a share block without payload bytes.
type emptyShareBodyError struct {
	Position int
}

func (e emptyShareBodyError) Error() string {
	return fmt.Sprintf("share %d: empty share body", e.Position)
}

// insufficientSharesError reports that fewer shares than the encoded threshold
// were provided.
type insufficientSharesError struct {
	Got  int
	Need int
}

func (e insufficientSharesError) Error() string {
	return fmt.Sprintf("insufficient shares (got %d, must be >= %d)", e.Got, e.Need)
}
