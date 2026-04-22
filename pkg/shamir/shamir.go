// Package shamir implements Shamir's Secret Sharing over GF(2^8).
package shamir

import "crypto/rand"

// MaxParts is the largest number of shares Split can produce because each
// share stores its x-coordinate in a single non-zero byte.
const MaxParts = 255

// MinThreshold is the smallest threshold Split accepts to ensure the secret is
// reconstructed from multiple shares rather than a single share.
const MinThreshold = 2

// MinCombineShares is the fewest shares Combine accepts before attempting
// polynomial interpolation.
const MinCombineShares = 2

// MinShareLength is the smallest valid encoded share length, consisting only
// of the trailing x-coordinate byte and an empty secret payload.
const MinShareLength = 1

// Split divides a secret into shares using Shamir's Secret Sharing over GF(2^8).
// Reconstructing the original secret requires at least threshold shares.
// Constraints: 2 <= threshold <= parts <= 255.
// Each share is len(secret)+1 bytes long; the last byte stores its unique
// non-zero x-coordinate, and the preceding bytes store the evaluated secret
// polynomial values.
// The returned share format does not encode threshold, so callers that persist
// or transport shares must track that value separately before calling Combine.
func Split(secret []byte, parts, threshold int) ([][]byte, error) {
	if parts > MaxParts {
		return nil, PartsOverLimitError{Parts: parts, Max: MaxParts}
	}

	if threshold < MinThreshold {
		return nil, ThresholdTooSmallError{Threshold: threshold, Min: MinThreshold}
	}

	if parts < threshold {
		return nil, PartsBelowThresholdError{Parts: parts, Threshold: threshold}
	}

	last := len(secret)

	shares := make([][]byte, parts)

	for i := range parts {
		x := uint8(i + 1)
		shares[i] = make([]byte, last+1)
		shares[i][last] = x
	}

	for j, value := range secret {
		coefficients := polyGenerate(threshold-1, value)
		for _, share := range shares {
			share[j] = polyEvaluate(coefficients, share[last])
		}
	}

	return shares, nil
}

// Combine reconstructs the secret from shares produced by Split.
// It validates only the share encoding: callers must provide at least two
// non-empty shares of the same length, each with a distinct non-zero
// x-coordinate stored in the last byte.
// The share format does not encode the original threshold, so Combine cannot
// verify that enough shares were provided. Callers must enforce that
// precondition before calling; otherwise Combine may return incorrect data
// without reporting an error.
func Combine(shares [][]byte) ([]byte, error) {
	if len(shares) < MinCombineShares {
		return nil, SharesTooFewError{
			Count: len(shares),
			Min:   MinCombineShares,
		}
	}

	shareLen := 0
	last := 0
	xCoordinates := make([]uint8, len(shares))

	seen := make(map[uint8]int, len(shares))

	for i, share := range shares {
		if len(share) < MinShareLength {
			return nil, ShareTooShortError{
				Index:  i,
				Length: len(share),
				Min:    MinShareLength,
			}
		}

		if i == 0 {
			shareLen = len(share)
			last = shareLen - 1
		} else if len(share) != shareLen {
			return nil, ShareLengthMismatchError{
				Index:  i,
				Length: len(share),
				Want:   shareLen,
			}
		}

		xCoordinate := share[last]

		if xCoordinate == 0 {
			return nil, ShareXZeroError{Index: i}
		}

		if previousIndex, exists := seen[xCoordinate]; exists {
			return nil, ShareXDuplicateError{
				Index:     i,
				PrevIndex: previousIndex,
				X:         xCoordinate,
			}
		}

		seen[xCoordinate] = i
		xCoordinates[i] = xCoordinate
	}

	weights := polyWeights(xCoordinates, 0)
	secret := make([]byte, shareLen-1)

	for j := range secret {
		var value uint8
		for i, share := range shares {
			value = fieldAdd(value, fieldMul(weights[i], share[j]))
		}

		secret[j] = value
	}

	return secret, nil
}

// polyGenerate returns a random polynomial whose constant term is intercept.
// Caller must ensure degree >= 0. Coefficients are ordered from x^0 upward;
// when degree > 0, the leading coefficient is guaranteed non-zero.
func polyGenerate(degree int, intercept uint8) []uint8 {
	coefficients := make([]uint8, degree+1)

	coefficients[0] = intercept

	if degree > 0 {
		// crypto/rand.Read always returns len(p), nil since Go 1.20;
		// it panics instead of returning an error on failure.
		_, _ = rand.Read(coefficients[1:])
		for coefficients[degree] == 0 {
			_, _ = rand.Read(coefficients[degree:])
		}
	}

	return coefficients
}

// polyEvaluate evaluates the polynomial at x using Horner's method. Caller
// must provide at least one coefficient ordered from x^0 upward.
func polyEvaluate(coefficients []uint8, x uint8) uint8 {
	var y uint8
	for i := len(coefficients) - 1; i >= 0; i-- {
		y = fieldAdd(fieldMul(y, x), coefficients[i])
	}

	return y
}

// polyWeights returns the Lagrange basis weights for interpolating the
// polynomial defined by xCoordinates at x. Caller must provide distinct
// x-coordinates.
func polyWeights(xCoordinates []uint8, x uint8) []uint8 {
	weights := make([]uint8, len(xCoordinates))
	for i := range xCoordinates {
		weights[i] = 1
		for j := range xCoordinates {
			if i == j {
				continue
			}

			weights[i] = fieldMul(weights[i], fieldDiv(
				fieldAdd(x, xCoordinates[j]),
				fieldAdd(xCoordinates[i], xCoordinates[j]),
			))
		}
	}

	return weights
}

// fieldAdd returns x + y in GF(2^8). In characteristic 2, addition equals
// bitwise XOR and subtraction coincides with addition, so there is no fieldSub.
func fieldAdd(x, y uint8) uint8 {
	return x ^ y
}

// fieldMul returns x * y in GF(2^8) via constant-time multiplication reduced
// by the AES polynomial x^8+x^4+x^3+x+1 (0x11b); 0x1b is its low 8 bits,
// XOR'd in at each left-shift step for modular reduction.
func fieldMul(x, y uint8) uint8 {
	var z uint8
	for i := 7; i >= 0; i-- {
		z = (z << 1) ^ (-(z >> 7) & 0x1b) ^ (-(x >> i & 1) & y)
	}

	return z
}

// fieldDiv returns x / y in GF(2^8), computed as x * fieldInv(y). Caller must
// ensure y != 0.
func fieldDiv(x, y uint8) uint8 {
	return fieldMul(x, fieldInv(y))
}

// fieldInv returns x^(-1) in GF(2^8), the unique y satisfying x * y == 1.
// Caller must ensure x != 0. By Fermat's little theorem x^(-1) = x^254; the
// addition chain below builds up to x^127, then squares it to obtain x^254.
func fieldInv(x uint8) uint8 {
	x2 := fieldMul(x, x)
	x3 := fieldMul(x2, x)
	x6 := fieldMul(x3, x3)
	x12 := fieldMul(x6, x6)
	x15 := fieldMul(x12, x3)
	x24 := fieldMul(x12, x12)
	x48 := fieldMul(x24, x24)
	x63 := fieldMul(x48, x15)
	x126 := fieldMul(x63, x63)
	x127 := fieldMul(x126, x)

	return fieldMul(x127, x127)
}
