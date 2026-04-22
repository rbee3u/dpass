package shamir

import "fmt"

// PartsOverLimitError reports that Split received more parts than the
// share format can encode in its one-byte x-coordinate.
type PartsOverLimitError struct {
	Parts int
	Max   int
}

func (e PartsOverLimitError) Error() string {
	return fmt.Sprintf("shamir: invalid parts (got %d, must be <= %d)", e.Parts, e.Max)
}

// ThresholdTooSmallError reports that Split received a threshold smaller than
// the minimum needed to reconstruct a secret from multiple shares.
type ThresholdTooSmallError struct {
	Threshold int
	Min       int
}

func (e ThresholdTooSmallError) Error() string {
	return fmt.Sprintf("shamir: invalid threshold (got %d, must be >= %d)", e.Threshold, e.Min)
}

// PartsBelowThresholdError reports that Split received fewer parts than the
// threshold required to reconstruct the secret.
type PartsBelowThresholdError struct {
	Parts     int
	Threshold int
}

func (e PartsBelowThresholdError) Error() string {
	return fmt.Sprintf("shamir: invalid parts (got %d, must be >= threshold %d)", e.Parts, e.Threshold)
}

// SharesTooFewError reports that Combine received fewer shares than the
// minimum required to interpolate a non-trivial polynomial.
type SharesTooFewError struct {
	Count int
	Min   int
}

func (e SharesTooFewError) Error() string {
	return fmt.Sprintf("shamir: insufficient shares (got %d, must be >= %d)", e.Count, e.Min)
}

// ShareTooShortError reports that Combine received a share that is too short
// to contain both payload bytes and the trailing x-coordinate byte.
type ShareTooShortError struct {
	Index  int
	Length int
	Min    int
}

func (e ShareTooShortError) Error() string {
	return fmt.Sprintf("shamir: share %d: invalid length (got %d, must be >= %d)", e.Index, e.Length, e.Min)
}

// ShareLengthMismatchError reports that Combine received a share whose
// length does not match the first validated share.
type ShareLengthMismatchError struct {
	Index  int
	Length int
	Want   int
}

func (e ShareLengthMismatchError) Error() string {
	return fmt.Sprintf("shamir: share %d: inconsistent length (got %d, want %d)", e.Index, e.Length, e.Want)
}

// ShareXZeroError reports that Combine received a share whose trailing
// x-coordinate byte is zero, which the share format reserves.
type ShareXZeroError struct {
	Index int
}

func (e ShareXZeroError) Error() string {
	return fmt.Sprintf("shamir: share %d: x-coordinate 0 is reserved", e.Index)
}

// ShareXDuplicateError reports that Combine received two shares with the
// same non-zero x-coordinate, which makes interpolation invalid.
type ShareXDuplicateError struct {
	Index     int
	PrevIndex int
	X         uint8
}

func (e ShareXDuplicateError) Error() string {
	return fmt.Sprintf("shamir: share %d: x-coordinate %d duplicates share %d", e.Index, e.X, e.PrevIndex)
}
