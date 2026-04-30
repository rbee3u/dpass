package shamir

import "fmt"

// SplitConstraintError reports that Split received parameters that violate the
// fixed constraint MinShares <= threshold <= parts <= MaxShares. Callers can
// inspect Threshold and Parts to determine which clause failed.
type SplitConstraintError struct {
	// Parts is the requested total share count.
	Parts int
	// Threshold is the requested reconstruction threshold.
	Threshold int
}

func (e SplitConstraintError) Error() string {
	return fmt.Sprintf(
		"shamir: invalid split parameters (got threshold=%d, parts=%d, want %d <= threshold <= parts <= %d)",
		e.Threshold, e.Parts, MinShares, MaxShares,
	)
}

// SharesTooFewError reports that Combine received fewer than MinShares shares, so
// interpolation cannot begin.
type SharesTooFewError struct {
	// Count is the number of shares supplied to Combine.
	Count int
}

func (e SharesTooFewError) Error() string {
	return fmt.Sprintf("shamir: insufficient shares (got %d, must be >= %d)", e.Count, MinShares)
}

// ShareTooShortError reports that Combine received a share shorter than
// MinShareLength, so it cannot contain the trailing x-coordinate byte.
type ShareTooShortError struct {
	// Index is the zero-based position of the rejected share in the input slice.
	Index int
	// Length is the actual share length in bytes.
	Length int
}

func (e ShareTooShortError) Error() string {
	return fmt.Sprintf("shamir: share %d: invalid length (got %d, must be >= %d)", e.Index, e.Length, MinShareLength)
}

// ShareLengthMismatchError reports that Combine received a share whose length does
// not match the first validated share, so all inputs cannot describe the same
// encoded secret.
type ShareLengthMismatchError struct {
	// Index is the zero-based position of the mismatched share in the input slice.
	Index int
	// Length is the actual share length in bytes.
	Length int
	// Want is the share length established by the first validated share.
	Want int
}

func (e ShareLengthMismatchError) Error() string {
	return fmt.Sprintf("shamir: share %d: inconsistent length (got %d, want %d)", e.Index, e.Length, e.Want)
}

// ShareXZeroError reports that Combine received a share whose trailing
// x-coordinate byte is zero, which the share format reserves.
type ShareXZeroError struct {
	// Index is the zero-based position of the rejected share in the input slice.
	Index int
}

func (e ShareXZeroError) Error() string {
	return fmt.Sprintf("shamir: share %d: x-coordinate 0 is reserved", e.Index)
}

// ShareXDuplicateError reports that Combine received two shares with the same
// non-zero x-coordinate, so interpolation no longer has distinct points.
type ShareXDuplicateError struct {
	// Index is the zero-based position of the duplicate share in the input slice.
	Index int
	// XCoordinate is the duplicated non-zero x-coordinate.
	XCoordinate uint8
	// PrevIndex is the zero-based position of the earlier share with the same x-coordinate.
	PrevIndex int
}

func (e ShareXDuplicateError) Error() string {
	return fmt.Sprintf("shamir: share %d: x-coordinate %d duplicates share %d", e.Index, e.XCoordinate, e.PrevIndex)
}
