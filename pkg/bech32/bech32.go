// Package bech32 encodes data as Bech32 strings.
package bech32

import (
	"bytes"
	"fmt"
)

// alphabet is the Bech32 character set in value order (indices 0–31).
const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// EmptyHrpError reports a missing human-readable part.
type EmptyHrpError struct{}

func (e EmptyHrpError) Error() string {
	return "bech32: empty HRP"
}

// InvalidHrpCharError reports an unsupported HRP byte.
type InvalidHrpCharError struct {
	// Char is the offending HRP byte.
	Char byte
}

func (e InvalidHrpCharError) Error() string {
	return fmt.Sprintf("bech32: invalid HRP character %#U", e.Char)
}

// InvalidDataValueError reports a value outside the 5-bit Bech32 alphabet range.
type InvalidDataValueError struct {
	// Part identifies whether the invalid value came from the version prefix or payload.
	Part string
	// Offset is the zero-based position within Part.
	Offset int
	// Value is the out-of-range 5-bit value.
	Value byte
}

func (e InvalidDataValueError) Error() string {
	return fmt.Sprintf("bech32: invalid %s value at offset %d (got %d, must be <= 31)", e.Part, e.Offset, e.Value)
}

// Encode returns a Bech32 string: hrp + "1" + payload + 6 checksum characters.
// vs is prepended to the payload as 5-bit values (for example, a witness version),
// while in is repacked from bytes into 5-bit groups before the checksum is appended.
// It returns an error when hrp or any 5-bit value is invalid.
func Encode(hrp string, vs, in []byte) (string, error) {
	if len(hrp) == 0 {
		return "", EmptyHrpError{}
	}
	for i := range len(hrp) {
		if hrp[i] < 33 || hrp[i] > 126 || ('A' <= hrp[i] && hrp[i] <= 'Z') {
			return "", InvalidHrpCharError{Char: hrp[i]}
		}
	}
	for i := range vs {
		if vs[i] >= 32 {
			return "", InvalidDataValueError{Part: "version", Offset: i, Value: vs[i]}
		}
	}

	vsin, remain, shift := bytes.Clone(vs), uint32(0), 0
	for i := range in {
		remain, shift = (remain<<8)|uint32(in[i]), shift+8
		for shift >= 5 {
			shift -= 5
			vsin = append(vsin, byte(remain>>shift))
			remain &= (1 << shift) - 1
		}
	}
	if shift > 0 {
		vsin = append(vsin, byte(remain<<(5-shift)))
	}

	data := make([]byte, 0, len(hrp)+1+len(vsin))
	data = append(data, hrp...)
	data = append(data, '1')
	for i := range vsin {
		if vsin[i] >= 32 {
			return "", InvalidDataValueError{Part: "payload", Offset: i, Value: vsin[i]}
		}
		data = append(data, alphabet[vsin[i]])
	}

	polymod := uint32(1)
	iterate := func(value uint32) {
		polymod, value = ((polymod&0x1ffffff)<<5)^value, polymod
		polymod ^= (1 & (value >> 25)) * 0x3b6a57b2
		polymod ^= (1 & (value >> 26)) * 0x26508e6d
		polymod ^= (1 & (value >> 27)) * 0x1ea119fa
		polymod ^= (1 & (value >> 28)) * 0x3d4233dd
		polymod ^= (1 & (value >> 29)) * 0x2a1462b3
	}
	for i := range len(hrp) {
		iterate(uint32(hrp[i] >> 5))
	}
	iterate(0)
	for i := range len(hrp) {
		iterate(uint32(hrp[i] & 31))
	}
	for i := range vsin {
		iterate(uint32(vsin[i]))
	}
	for range 6 {
		iterate(0)
	}

	return string(append(data,
		alphabet[(polymod>>25)&31], alphabet[(polymod>>20)&31], alphabet[(polymod>>15)&31],
		alphabet[(polymod>>10)&31], alphabet[(polymod>>5)&31], alphabet[(polymod^1)&31],
	)), nil
}
