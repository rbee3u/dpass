package qrcode

import (
	"fmt"
	"strings"
)

// invalidLevelError reports a --level flag outside the accepted error-correction levels.
type invalidLevelError struct {
	// Got is the level value provided by the caller.
	Got string
}

func (e invalidLevelError) Error() string {
	return fmt.Sprintf("invalid level (got %q, must be one of %s)",
		e.Got, strings.Join([]string{levelL, levelM, levelQ, levelH}, " / "))
}

// invalidQuietError reports a --quiet flag outside the accepted quiet-zone range.
type invalidQuietError struct {
	// Got is the quiet-zone size provided by the caller.
	Got int
}

func (e invalidQuietError) Error() string {
	return fmt.Sprintf("invalid quiet (got %d, must be within [%d, %d])", e.Got, quietMin, quietMax)
}

// inputTooLongError reports a stdin payload larger than the accepted limit.
type inputTooLongError struct {
	// Got is the input length in bytes.
	Got int
}

func (e inputTooLongError) Error() string {
	return fmt.Sprintf("invalid input length (got %d bytes, must be <= %d bytes)", e.Got, maxInputBytes)
}
