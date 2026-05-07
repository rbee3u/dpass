package bitcoin

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rbee3u/dpass/pkg/bip32"
)

// invalidPurposeError reports a --purpose flag outside the accepted BIP purposes.
type invalidPurposeError struct {
	// Got is the purpose value provided by the caller.
	Got uint32
	// Allowed lists the accepted BIP purpose values for this command.
	Allowed []uint32
}

func (e invalidPurposeError) Error() string {
	values := make([]string, len(e.Allowed))
	for i, v := range e.Allowed {
		values[i] = strconv.FormatUint(uint64(v), 10)
	}
	return fmt.Sprintf("invalid purpose (got %d, must be one of %s)", e.Got, strings.Join(values, " / "))
}

// invalidAccountError reports a --account flag that would exceed the hardened boundary.
type invalidAccountError struct {
	// Got is the account value provided by the caller.
	Got uint32
}

func (e invalidAccountError) Error() string {
	return fmt.Sprintf("invalid account (got %d, must be < %d)", e.Got, bip32.FirstHardenedChild)
}

// invalidChangeError reports a --change flag outside the external/internal chain set.
type invalidChangeError struct {
	// Got is the change value provided by the caller.
	Got uint32
}

func (e invalidChangeError) Error() string {
	return fmt.Sprintf("invalid change (got %d, must be 0 or 1)", e.Got)
}

// invalidIndexError reports a --index flag that would exceed the hardened boundary.
type invalidIndexError struct {
	// Got is the index value provided by the caller.
	Got uint32
}

func (e invalidIndexError) Error() string {
	return fmt.Sprintf("invalid index (got %d, must be < %d)", e.Got, bip32.FirstHardenedChild)
}
