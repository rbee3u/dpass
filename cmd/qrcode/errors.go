package qrcode

import (
	"fmt"
	"strings"
)

// invalidLevelError reports a --level flag outside the accepted QR error-correction levels.
type invalidLevelError struct {
	// Got is the level value provided by the caller.
	Got string
	// Allowed lists the accepted QR error-correction levels.
	Allowed []string
}

func (e invalidLevelError) Error() string {
	return fmt.Sprintf("invalid level (got %q, must be one of %s)", e.Got, strings.Join(e.Allowed, " / "))
}

// invalidQuietError reports a --quiet flag outside the accepted quiet-zone range.
type invalidQuietError struct {
	// Got is the quiet-zone size provided by the caller.
	Got int
	// Min is the minimum accepted quiet-zone size.
	Min int
	// Max is the maximum accepted quiet-zone size.
	Max int
}

func (e invalidQuietError) Error() string {
	return fmt.Sprintf("invalid quiet (got %d, must be within [%d, %d])", e.Got, e.Min, e.Max)
}

// inputTooLongError reports a stdin payload larger than the accepted limit.
type inputTooLongError struct {
	// Got is the input length in bytes.
	Got int
	// Max is the maximum accepted input length in bytes.
	Max int
}

func (e inputTooLongError) Error() string {
	return fmt.Sprintf("invalid input length (got %d bytes, must be <= %d bytes)", e.Got, e.Max)
}
