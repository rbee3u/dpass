package sui

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
	change int32
}

func (e invalidChangeError) Error() string {
	return fmt.Sprintf(
		"invalid change %d (must be >= %d)",
		e.change, changeIgnore,
	)
}

type invalidIndexError struct {
	index         int32
	requireIgnore bool
}

func (e invalidIndexError) Error() string {
	if e.requireIgnore {
		return fmt.Sprintf(
			"invalid index %d (must be %d when change is %d)",
			e.index, indexIgnore, changeIgnore,
		)
	}
	return fmt.Sprintf(
		"invalid index %d (must be >= %d)",
		e.index, indexIgnore,
	)
}
