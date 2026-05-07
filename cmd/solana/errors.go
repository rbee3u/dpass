package solana

import (
	"fmt"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

// invalidAccountError reports a --account flag that would exceed the hardened boundary.
type invalidAccountError struct {
	// Got is the account value provided by the caller.
	Got uint32
}

func (e invalidAccountError) Error() string {
	return fmt.Sprintf("invalid account (got %d, must be < %d)", e.Got, bip3x.FirstHardenedChild)
}

// invalidChangeError reports a --change flag outside the accepted range. Use -1
// to omit the change segment and any following derivation-path segments.
type invalidChangeError struct {
	// Got is the change value provided by the caller.
	Got int32
}

func (e invalidChangeError) Error() string {
	return fmt.Sprintf("invalid change (got %d, must be >= %d)", e.Got, changeIgnore)
}

// invalidIndexError reports a --index flag outside the accepted range. When
// --change is -1, --index must also be -1.
type invalidIndexError struct {
	// Got is the index value provided by the caller.
	Got int32
	// RequireIgnore reports whether the current change setting requires indexIgnore.
	RequireIgnore bool
}

func (e invalidIndexError) Error() string {
	if e.RequireIgnore {
		return fmt.Sprintf("invalid index (got %d, must be %d when change is %d)", e.Got, indexIgnore, changeIgnore)
	}

	return fmt.Sprintf("invalid index (got %d, must be >= %d)", e.Got, indexIgnore)
}
