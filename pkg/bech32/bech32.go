// Package bech32 encodes data as Bech32 strings.
package bech32

import (
	"bytes"
	"fmt"
)

// alphabet is the Bech32 character set in value order (indices 0–31).
const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

const (
	bech32ChecksumConstant  = uint32(1)
	bech32mChecksumConstant = uint32(0x2bc830a3)
)

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

// InvalidWitnessVersionError reports a SegWit witness version outside the supported range.
type InvalidWitnessVersionError struct {
	Version byte
}

func (e InvalidWitnessVersionError) Error() string {
	return fmt.Sprintf("bech32: invalid witness version %d (must be between 0 and 16)", e.Version)
}

// InvalidWitnessProgramLengthError reports a SegWit witness program with an
// unsupported size.
type InvalidWitnessProgramLengthError struct {
	Version byte
	Length  int
}

func (e InvalidWitnessProgramLengthError) Error() string {
	if e.Version == 0 {
		return fmt.Sprintf(
			"bech32: invalid witness program length %d for version %d (must be 20 or 32)",
			e.Length, e.Version,
		)
	}
	return fmt.Sprintf(
		"bech32: invalid witness program length %d for version %d (must be between 2 and 40)",
		e.Length, e.Version,
	)
}

// Encode returns a Bech32 string: hrp + "1" + payload + 6 checksum characters.
// vs is prepended to the payload as 5-bit values (for example, a witness
// version), while in is repacked from bytes into 5-bit groups before the
// checksum is appended. It returns an error when hrp or any 5-bit value is invalid.
func Encode(hrp string, vs, in []byte) (string, error) {
	return encode(hrp, vs, in, bech32ChecksumConstant)
}

// EncodeSegWit returns a SegWit address using Bech32 for witness version 0 and
// Bech32m for witness versions 1 through 16.
func EncodeSegWit(hrp string, witnessVersion byte, witnessProgram []byte) (string, error) {
	if witnessVersion > 16 {
		return "", InvalidWitnessVersionError{Version: witnessVersion}
	}
	if len(witnessProgram) < 2 || len(witnessProgram) > 40 {
		return "", InvalidWitnessProgramLengthError{
			Version: witnessVersion,
			Length:  len(witnessProgram),
		}
	}
	if witnessVersion == 0 && len(witnessProgram) != 20 && len(witnessProgram) != 32 {
		return "", InvalidWitnessProgramLengthError{
			Version: witnessVersion,
			Length:  len(witnessProgram),
		}
	}

	checksumConstant := bech32mChecksumConstant
	if witnessVersion == 0 {
		checksumConstant = bech32ChecksumConstant
	}
	return encode(hrp, []byte{witnessVersion}, witnessProgram, checksumConstant)
}

func encode(hrp string, vs, in []byte, checksumConstant uint32) (string, error) {
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
	polymod ^= checksumConstant

	return string(append(data,
		alphabet[(polymod>>25)&31], alphabet[(polymod>>20)&31], alphabet[(polymod>>15)&31],
		alphabet[(polymod>>10)&31], alphabet[(polymod>>5)&31], alphabet[polymod&31],
	)), nil
}
