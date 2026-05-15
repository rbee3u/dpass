package helper

import "fmt"

// InputTooLongError reports an input payload larger than the accepted limit.
type InputTooLongError struct {
	// Limit is the maximum accepted input length in bytes.
	Limit int
}

func (e InputTooLongError) Error() string {
	return fmt.Sprintf(
		"input too long (must be <= %d bytes)",
		e.Limit,
	)
}
