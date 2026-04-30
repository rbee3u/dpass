package bitcoin

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

// invalidPurposeError reports a --purpose flag outside the accepted BIP purposes.
type invalidPurposeError struct {
	Got     uint32
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

// invalidDecompressPurposeError reports --decompress used with SegWit purposes.
type invalidDecompressPurposeError struct {
	Purpose uint32
}

func (e invalidDecompressPurposeError) Error() string {
	return fmt.Sprintf("invalid decompress mode (purpose %d requires compressed public keys)", e.Purpose)
}
