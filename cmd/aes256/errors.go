package aes256

import "fmt"

type invalidPayloadLengthError struct {
	length    int
	minLength int
}

func (e invalidPayloadLengthError) Error() string {
	return fmt.Sprintf(
		"invalid payload length %d (must be >= %d)",
		e.length, e.minLength,
	)
}
