package shamir

import (
	"errors"
	"fmt"
)

var (
	// errMalformedPEMInput reports trailing non-PEM data after decoding share blocks.
	errMalformedPEMInput = errors.New("malformed PEM input")
	// errNoSharesProvided reports that combine received no PEM blocks.
	errNoSharesProvided = errors.New("no shares provided")
)

// unexpectedBlockTypeError reports a PEM block type other than the expected share type.
type unexpectedBlockTypeError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Got is the PEM block type found in the current share.
	Got string
	// Want is the PEM block type expected by the command.
	Want string
}

func (e unexpectedBlockTypeError) Error() string {
	return fmt.Sprintf("share %d: unexpected block type (got %q, want %q)", e.Pos, e.Got, e.Want)
}

// missingHeaderError reports a required PEM header key absent from a share block.
type missingHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Key is the missing PEM header name.
	Key string
}

func (e missingHeaderError) Error() string {
	return fmt.Sprintf("share %d: missing %s header", e.Pos, e.Key)
}

// unparsableHeaderError reports a PEM header value that failed to parse.
type unparsableHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Key is the PEM header name that failed to parse.
	Key string
	// Value is the raw PEM header value that failed to parse.
	Value string
	// Err is the underlying parse error.
	Err error
}

func (e unparsableHeaderError) Error() string {
	return fmt.Sprintf("share %d: invalid %s header (got %q): %v", e.Pos, e.Key, e.Value, e.Err)
}

func (e unparsableHeaderError) Unwrap() error {
	return e.Err
}

// invalidHeaderError reports a PEM header value outside the supported range.
type invalidHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Key is the PEM header name whose value was rejected.
	Key string
	// Value is the parsed header value that violated command constraints.
	Value int
	// Detail explains the violated constraint in human-readable form.
	Detail string
}

func (e invalidHeaderError) Error() string {
	return fmt.Sprintf("share %d: invalid %s header %d (%s)", e.Pos, e.Key, e.Value, e.Detail)
}

// emptyShareBodyError reports a share block without payload bytes.
type emptyShareBodyError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
}

func (e emptyShareBodyError) Error() string {
	return fmt.Sprintf("share %d: empty share body", e.Pos)
}

// tooManySharesError reports more shares than the declared N header.
type tooManySharesError struct {
	// Got is the number of shares provided by the caller.
	Got int
	// Max is the maximum share count allowed by the encoded N header.
	Max int
}

func (e tooManySharesError) Error() string {
	return fmt.Sprintf("too many shares (got %d, must be <= %d)", e.Got, e.Max)
}

// inconsistentHeaderError reports that share headers disagree on a field value.
type inconsistentHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Key is the PEM header name whose value disagreed.
	Key string
	// Got is the parsed header value from the current share.
	Got int
	// Want is the header value established by previous shares.
	Want int
}

func (e inconsistentHeaderError) Error() string {
	return fmt.Sprintf("share %d: inconsistent %s header (got %d, want %d)", e.Pos, e.Key, e.Got, e.Want)
}

// duplicateHeaderValueError reports two shares claiming the same header value.
type duplicateHeaderValueError struct {
	// Pos is the zero-based position of the duplicate share in the parsed input stream.
	Pos int
	// Key is the PEM header name that duplicated an earlier value.
	Key string
	// Value is the duplicated parsed header value.
	Value int
	// PrevPos is the zero-based position of the earlier share with the same value.
	PrevPos int
}

func (e duplicateHeaderValueError) Error() string {
	return fmt.Sprintf("share %d: duplicate %s header %d (already used by share %d)", e.Pos, e.Key, e.Value, e.PrevPos)
}

// insufficientSharesError reports that fewer shares than the encoded threshold
// were provided.
type insufficientSharesError struct {
	// Got is the number of shares provided by the caller.
	Got int
	// Need is the minimum share count required by the encoded threshold.
	Need int
}

func (e insufficientSharesError) Error() string {
	return fmt.Sprintf("insufficient shares (got %d, must be >= %d)", e.Got, e.Need)
}
