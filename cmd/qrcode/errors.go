package qrcode

import (
	"fmt"
	"strings"
)

// invalidLevelError reports a --level flag outside the accepted QR error-correction levels.
type invalidLevelError struct {
	Got     string
	Allowed []string
}

func (e invalidLevelError) Error() string {
	return fmt.Sprintf("invalid level (got %q, want one of %s)", e.Got, strings.Join(e.Allowed, "/"))
}

// invalidQuietError reports a --quiet flag outside the accepted quiet-zone range.
type invalidQuietError struct {
	Got int
	Min int
	Max int
}

func (e invalidQuietError) Error() string {
	return fmt.Sprintf("invalid quiet (got %d, must be within [%d, %d])", e.Got, e.Min, e.Max)
}

// inputTooLongError reports a stdin payload larger than the accepted limit.
type inputTooLongError struct {
	Got int
	Max int
}

func (e inputTooLongError) Error() string {
	return fmt.Sprintf("invalid input length (got %d bytes, must be <= %d bytes)", e.Got, e.Max)
}
