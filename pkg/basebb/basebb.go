// Package basebb converts big-endian digit streams between arbitrary bases.
package basebb

import "math"

// MinBase is the smallest radix supported for digit conversion.
const MinBase uint32 = 2

// Transform converts a big-endian digit stream from inBase to outBase. Each
// element of in is one digit in [0, inBase). Leading zeros are preserved.
func Transform(inBase, outBase uint32, in []uint32) ([]uint32, error) {
	if inBase < MinBase {
		return nil, InvalidInBaseError{InBase: inBase}
	}
	if outBase < MinBase {
		return nil, InvalidOutBaseError{OutBase: outBase}
	}
	zeros := 0
	for zeros < len(in) && in[zeros] == 0 {
		zeros++
	}
	ioRatio := math.Log(float64(inBase)) / math.Log(float64(outBase))
	// Add one slot to absorb the rounding error of ceil(n*ioRatio) when ioRatio
	// is approximated in float64. The unused leading slot is trimmed by the
	// final reslice, so +1 is always sufficient for any slice length the
	// runtime can allocate.
	out := make([]uint32, zeros+int(math.Ceil(float64(len(in)-zeros)*ioRatio))+1)
	start := len(out)
	for i := range in {
		if in[i] >= inBase {
			return nil, InvalidDigitError{Offset: i, Digit: in[i], InBase: inBase}
		}
		carry, index := uint64(in[i]), len(out)-1
		for carry != 0 || index >= start {
			carry += uint64(out[index]) * uint64(inBase)
			out[index] = uint32(carry % uint64(outBase))
			carry, index = carry/uint64(outBase), index-1
		}
		start = index + 1
	}
	return out[start-zeros:], nil
}
