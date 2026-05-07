package shamir

import (
	"errors"
	"fmt"

	"github.com/rbee3u/dpass/pkg/shamir"
)

var (
	// errMalformedPEMInput reports input that cannot be fully decoded into
	// consecutive PEM-encoded share blocks.
	errMalformedPEMInput = errors.New("malformed PEM input")
	// errNoSharesProvided reports that combine received no PEM blocks.
	errNoSharesProvided = errors.New("no shares provided")
)

// unexpectedBlockTypeError reports a PEM block type other than the expected share type.
type unexpectedBlockTypeError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Got is the PEM block type declared by the share at Pos.
	Got string
	// Want is the only PEM block type accepted by the combine command.
	Want string
}

func (e unexpectedBlockTypeError) Error() string {
	return fmt.Sprintf("share %d: unexpected block type (got %q, want %q)", e.Pos, e.Got, e.Want)
}

// missingHeaderError reports a required PEM header key absent from a share block.
type missingHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Key identifies which required share metadata header is absent.
	Key string
}

func (e missingHeaderError) Error() string {
	return fmt.Sprintf("share %d: missing %s header", e.Pos, e.Key)
}

// malformedHeaderError reports a PEM header value that failed to parse.
type malformedHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Key identifies which share metadata header failed integer parsing.
	Key string
	// Value preserves the raw header text before strconv.Atoi rejects it.
	Value string
	// Err is the wrapped parse failure returned by strconv.Atoi.
	Err error
}

func (e malformedHeaderError) Error() string {
	return fmt.Sprintf("share %d: malformed %s header %q: %v", e.Pos, e.Key, e.Value, e.Err)
}

func (e malformedHeaderError) Unwrap() error {
	return e.Err
}

// invalidHeaderError reports share headers that do not satisfy the combined
// metadata constraints.
type invalidHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Parts is the parsed total-share count from the N header at Pos.
	Parts int
	// Threshold is the parsed reconstruction threshold from the M header at Pos.
	Threshold int
	// Index is the parsed share identifier from the I header at Pos.
	Index int
}

func (e invalidHeaderError) Error() string {
	return fmt.Sprintf(
		"share %d: invalid header constraints (got N=%d, M=%d, I=%d, want %d <= M <= N <= %d, 0 <= I < N)",
		e.Pos, e.Parts, e.Threshold, e.Index, shamir.MinShares, shamir.MaxShares,
	)
}

// inconsistentHeaderError reports that share headers disagree on a field value.
type inconsistentHeaderError struct {
	// Pos is the zero-based share position in the parsed input stream.
	Pos int
	// Key names the metadata header whose value diverged at Pos.
	Key string
	// Got is the parsed value carried by the share at Pos.
	Got int
	// Want is the value established by the earlier validated shares.
	Want int
}

func (e inconsistentHeaderError) Error() string {
	return fmt.Sprintf("share %d: inconsistent %s header (got %d, want %d)", e.Pos, e.Key, e.Got, e.Want)
}

// duplicateHeaderError reports two shares claiming the same header value.
type duplicateHeaderError struct {
	// Pos is the zero-based position of the duplicate share in the parsed input stream.
	Pos int
	// Key names the metadata header whose value must stay unique across shares.
	Key string
	// Value is the parsed header value already claimed by an earlier share.
	Value int
	// PrevPos is the zero-based position of the first share that used Value.
	PrevPos int
}

func (e duplicateHeaderError) Error() string {
	return fmt.Sprintf("share %d: duplicate %s header %d (already used by share %d)", e.Pos, e.Key, e.Value, e.PrevPos)
}

// insufficientSharesError reports that fewer shares than the encoded threshold
// were provided.
type insufficientSharesError struct {
	// Got is the number of validated shares supplied to combine.
	Got int
	// Need is the minimum share count declared by the shared M header value.
	Need int
}

func (e insufficientSharesError) Error() string {
	return fmt.Sprintf("insufficient shares (got %d, must be >= %d)", e.Got, e.Need)
}
