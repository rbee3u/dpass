package dogecoin

import (
	"fmt"

	"github.com/rbee3u/dpass/pkg/bip32"
)

type invalidAccountError struct {
	account uint32
}

func (e invalidAccountError) Error() string {
	return fmt.Sprintf(
		"invalid account %d (must be < %d)",
		e.account, bip32.FirstHardenedChild,
	)
}

type invalidChangeError struct {
	change uint32
}

func (e invalidChangeError) Error() string {
	return fmt.Sprintf(
		"invalid change %d (must be 0 or 1)",
		e.change,
	)
}

type invalidIndexError struct {
	index uint32
}

func (e invalidIndexError) Error() string {
	return fmt.Sprintf(
		"invalid index %d (must be < %d)",
		e.index, bip32.FirstHardenedChild,
	)
}
