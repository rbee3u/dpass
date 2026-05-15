package bip32

import (
	"errors"
	"fmt"
)

// ErrInvalidSecp256k1MasterKey reports a master scalar that is zero or not less
// than the secp256k1 group order.
var ErrInvalidSecp256k1MasterKey = errors.New("bip32: invalid secp256k1 master key")

// InvalidSecp256k1InterKeyError reports an intermediate scalar (the left half
// of the HMAC output) that is not less than the secp256k1 group order at the
// given derivation step.
type InvalidSecp256k1InterKeyError struct {
	// Depth is the zero-based derivation step that produced the rejected scalar.
	Depth int
	// Index is the child index used at Depth.
	Index uint32
}

func (e InvalidSecp256k1InterKeyError) Error() string {
	return fmt.Sprintf(
		"bip32: invalid secp256k1 inter key at depth %d index %d",
		e.Depth, e.Index,
	)
}

// InvalidSecp256k1ChildKeyError reports a derived child scalar that reduces to
// zero modulo the secp256k1 group order at the given derivation step.
type InvalidSecp256k1ChildKeyError struct {
	// Depth is the zero-based derivation step that produced the rejected scalar.
	Depth int
	// Index is the child index used at Depth.
	Index uint32
}

func (e InvalidSecp256k1ChildKeyError) Error() string {
	return fmt.Sprintf(
		"bip32: invalid secp256k1 child key at depth %d index %d",
		e.Depth, e.Index,
	)
}

// InvalidEd25519PathError reports an ed25519 derivation path containing a
// non-hardened index.
type InvalidEd25519PathError struct {
	// Path is the full derivation path rejected by the ed25519 hardening rule.
	Path []uint32
}

func (e InvalidEd25519PathError) Error() string {
	return fmt.Sprintf(
		"bip32: invalid ed25519 derivation path %v (every index must be hardened)",
		e.Path,
	)
}
