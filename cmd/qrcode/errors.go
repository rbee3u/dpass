package qrcode

import "fmt"

type invalidLevelError struct {
	level string
}

func (e invalidLevelError) Error() string {
	return fmt.Sprintf(
		"invalid level %q (must be one of %s/%s/%s/%s)",
		e.level, levelL, levelM, levelQ, levelH,
	)
}

type invalidQuietError struct {
	quiet int
}

func (e invalidQuietError) Error() string {
	return fmt.Sprintf(
		"invalid quiet %d (must be within [%d, %d])",
		e.quiet, quietMin, quietMax,
	)
}
