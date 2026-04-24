package ethereum

import (
	"fmt"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

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
