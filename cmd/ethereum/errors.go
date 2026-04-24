package ethereum

import (
	"fmt"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

// invalidPurposeError reports a --purpose flag that would exceed the hardened boundary.
type invalidPurposeError struct {
	Got uint32
}

func (e invalidPurposeError) Error() string {
	return fmt.Sprintf("invalid purpose (got %d, must be < %d)", e.Got, bip3x.FirstHardenedChild)
}

// invalidCoinError reports a --coin flag that would exceed the hardened boundary.
type invalidCoinError struct {
	Got uint32
}

func (e invalidCoinError) Error() string {
	return fmt.Sprintf("invalid coin (got %d, must be < %d)", e.Got, bip3x.FirstHardenedChild)
}

// invalidAccountError reports a --account flag that would exceed the hardened boundary.
type invalidAccountError struct {
	Got uint32
}

func (e invalidAccountError) Error() string {
	return fmt.Sprintf("invalid account (got %d, must be < %d)", e.Got, bip3x.FirstHardenedChild)
}

// invalidChangeError reports a --change flag that would exceed the hardened boundary.
type invalidChangeError struct {
	Got uint32
}

func (e invalidChangeError) Error() string {
	return fmt.Sprintf("invalid change (got %d, must be < %d)", e.Got, bip3x.FirstHardenedChild)
}

// invalidIndexError reports a --index flag that would exceed the hardened boundary.
type invalidIndexError struct {
	Got uint32
}

func (e invalidIndexError) Error() string {
	return fmt.Sprintf("invalid index (got %d, must be < %d)", e.Got, bip3x.FirstHardenedChild)
}
