package basebb

import "fmt"

// InvalidInBaseError reports an input radix below MinBase.
type InvalidInBaseError struct {
	// InBase is the unsupported input radix supplied by the caller.
	InBase uint32
}

func (e InvalidInBaseError) Error() string {
	return fmt.Sprintf(
		"basebb: invalid in base %d (must be >= %d)",
		e.InBase, MinBase,
	)
}

// InvalidOutBaseError reports an output radix below MinBase.
type InvalidOutBaseError struct {
	// OutBase is the unsupported output radix supplied by the caller.
	OutBase uint32
}

func (e InvalidOutBaseError) Error() string {
	return fmt.Sprintf(
		"basebb: invalid out base %d (must be >= %d)",
		e.OutBase, MinBase,
	)
}

// InvalidDigitError reports an input digit whose value is not representable in
// the input base.
type InvalidDigitError struct {
	// Offset is the zero-based position of the rejected input digit.
	Offset int
	// Digit is the rejected value.
	Digit uint32
	// InBase is the input radix that Digit failed to fit into.
	InBase uint32
}

func (e InvalidDigitError) Error() string {
	return fmt.Sprintf(
		"basebb: invalid digit %d at offset %d (must be < %d)",
		e.Digit, e.Offset, e.InBase,
	)
}
