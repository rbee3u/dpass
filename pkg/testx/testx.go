// Package testx provides shared helpers for unit tests across cmd and pkg.
package testx

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

var (
	// ErrReadFailure is a shared sentinel error for tests that need to simulate
	// a reader failure. It is intended for use with NewReader to inject a
	// deterministic read error without each test defining its own sentinel.
	ErrReadFailure = errors.New("read failure")
	// ErrWriteFailure is a shared sentinel error for tests that need to
	// simulate a writer failure. It is intended for use with NewWriter to
	// inject a deterministic write error without each test defining its own sentinel.
	ErrWriteFailure = errors.New("write failure")
)

// Reader wraps a bytes.Reader for tests that need a deterministic trailing read
// error. It serves the provided slice without copying it and behaves like
// bytes.Reader until the input is exhausted. When the configured trailing error
// is non-nil, it replaces every EOF after the final byte, including the read
// that returns the last bytes and the trailing error together.
type Reader struct {
	r   *bytes.Reader
	err error
}

// NewReader returns a Reader over b with the configured trailing error. The
// caller must not mutate b while the Reader is in use, since b is retained
// without copying.
func NewReader(b []byte, err error) *Reader {
	return &Reader{r: bytes.NewReader(b), err: err}
}

// Read behaves like bytes.Reader.Read except for the configured trailing error.
// The trailing error also replaces io.EOF for zero-length reads after the input
// is exhausted.
func (r *Reader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if r.r.Len() == 0 && r.err != nil {
		err = r.err
	}
	return n, err
}

// Writer wraps a bytes.Buffer for tests that need deterministic write results.
// When the configured error is nil, the Writer behaves like a bytes.Buffer and
// appends each payload to the recorded bytes. When the configured error is
// non-nil, every write returns that error and replaces the previously recorded
// bytes with the latest payload, so tests can inspect exactly what the most
// recent failed write attempted to output.
type Writer struct {
	w   bytes.Buffer
	err error
}

// NewWriter returns a Writer with the configured write result error.
func NewWriter(err error) *Writer {
	return &Writer{err: err}
}

// Write appends p to the recorded bytes and returns the configured error. When
// the configured error is non-nil, the previously recorded bytes are reset
// before p is recorded.
func (w *Writer) Write(p []byte) (int, error) {
	if w.err != nil {
		w.w.Reset()
	}
	n, _ := w.w.Write(p)
	return n, w.err
}

// WriteString appends s to the recorded bytes and returns the configured error.
// When the configured error is non-nil, the previously recorded bytes are reset
// before s is recorded.
func (w *Writer) WriteString(s string) (int, error) {
	if w.err != nil {
		w.w.Reset()
	}
	n, _ := w.w.WriteString(s)
	return n, w.err
}

// Bytes returns the bytes recorded so far.
func (w *Writer) Bytes() []byte {
	return w.w.Bytes()
}

// String returns the string recorded so far.
func (w *Writer) String() string {
	return w.w.String()
}

// EqualSlice behaves like require.Equal for slices, except it also treats nil
// and empty slices as equal. When both want and got are empty, no assertion
// runs and msgAndArgs is unused.
func EqualSlice[T any](t require.TestingT, want, got []T, msgAndArgs ...any) {
	if h, _ := t.(interface{ Helper() }); h != nil {
		h.Helper()
	}
	if len(want) != 0 || len(got) != 0 {
		require.Equal(t, want, got, msgAndArgs...)
	}
}

// Stub swaps the target with the provided double and restores it on cleanup. It
// takes *testing.T because the restoration is registered via t.Cleanup.
func Stub[T any](t *testing.T, target *T, double T) {
	double, *target = *target, double
	t.Cleanup(func() { *target = double })
}
