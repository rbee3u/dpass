package shamir

import (
	"errors"
	"fmt"

	"github.com/rbee3u/dpass/pkg/shamir"
)

var (
	errMalformedPEMInput = errors.New("malformed PEM input")
	errNoSharesProvided  = errors.New("no shares provided")
)

type unexpectedBlockTypeError struct {
	pos  int
	got  string
	want string
}

func (e unexpectedBlockTypeError) Error() string {
	return fmt.Sprintf(
		"share %d: unexpected block type (got %q, want %q)",
		e.pos, e.got, e.want,
	)
}

type missingHeaderError struct {
	pos int
	key string
}

func (e missingHeaderError) Error() string {
	return fmt.Sprintf(
		"share %d: missing %s header",
		e.pos, e.key,
	)
}

type malformedHeaderError struct {
	pos   int
	key   string
	value string
	err   error
}

func (e malformedHeaderError) Error() string {
	return fmt.Sprintf(
		"share %d: malformed %s header %q: %v",
		e.pos, e.key, e.value, e.err,
	)
}

func (e malformedHeaderError) Unwrap() error {
	return e.err
}

type invalidHeaderError struct {
	pos       int
	parts     int
	threshold int
	index     int
}

func (e invalidHeaderError) Error() string {
	return fmt.Sprintf(
		"share %d: invalid header constraints (got N=%d, M=%d, I=%d, want %d <= M <= N <= %d, 0 <= I < N)",
		e.pos, e.parts, e.threshold, e.index, shamir.MinShares, shamir.MaxShares,
	)
}

type inconsistentHeaderError struct {
	pos  int
	key  string
	got  int
	want int
}

func (e inconsistentHeaderError) Error() string {
	return fmt.Sprintf(
		"share %d: inconsistent %s header (got %d, want %d)",
		e.pos, e.key, e.got, e.want,
	)
}

type duplicateHeaderError struct {
	pos     int
	key     string
	value   int
	prevPos int
}

func (e duplicateHeaderError) Error() string {
	return fmt.Sprintf(
		"share %d: duplicate %s header %d (already used by share %d)",
		e.pos, e.key, e.value, e.prevPos,
	)
}

type insufficientSharesError struct {
	got int
	min int
}

func (e insufficientSharesError) Error() string {
	return fmt.Sprintf(
		"insufficient shares (got %d, must be >= %d)",
		e.got, e.min,
	)
}
