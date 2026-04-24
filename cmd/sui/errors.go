package sui

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

// invalidChangeError reports a --change flag outside the accepted range.
// Use changeIgnore (-1) to omit the change segment from the derivation path.
type invalidChangeError struct {
	Got int32
}

func (e invalidChangeError) Error() string {
	return fmt.Sprintf("invalid change (got %d, must be >= %d)", e.Got, changeIgnore)
}

// invalidIndexError reports a --index flag outside the accepted range.
// When --change is changeIgnore, --index must also be indexIgnore.
type invalidIndexError struct {
	Got           int32
	RequireIgnore bool
}

func (e invalidIndexError) Error() string {
	if e.RequireIgnore {
		return fmt.Sprintf("invalid index (got %d, must be %d when change is %d)", e.Got, indexIgnore, changeIgnore)
	}

	return fmt.Sprintf("invalid index (got %d, must be >= %d)", e.Got, indexIgnore)
}
