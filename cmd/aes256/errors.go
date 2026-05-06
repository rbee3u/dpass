package aes256

import "fmt"

// invalidPayloadLengthError reports payload shorter than nonce plus the GCM tag.
type invalidPayloadLengthError struct {
	// Got is the decoded payload length in bytes.
	Got int
	// Min is the minimum decoded payload length: nonce plus GCM tag.
	Min int
}

func (e invalidPayloadLengthError) Error() string {
	return fmt.Sprintf("invalid payload length (got %d bytes, must be >= %d bytes)", e.Got, e.Min)
}
