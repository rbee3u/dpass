// Package bech32 encodes data as Bech32 and Bech32m strings.
package bech32

import (
	"bytes"
)

const (
	alphabet        = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
	minHrpLen       = 1
	maxHrpLen       = 83
	minHrpChar byte = 33
	maxHrpChar byte = 126
	maxVerByte byte = 31
)

// EncodeBech32 returns a Bech32 string: hrp + "1" + payload + 6 checksum
// characters. ver is prepended to the payload as 5-bit values, while in is
// repacked from bytes into 5-bit groups before the checksum is appended.
func EncodeBech32(hrp string, ver, in []byte) (string, error) {
	return encode(hrp, ver, in, 1)
}

// EncodeBech32m is like EncodeBech32 but uses the Bech32m polymod constant
// 0x2bc830a3, which offers stronger error detection.
func EncodeBech32m(hrp string, ver, in []byte) (string, error) {
	return encode(hrp, ver, in, 0x2bc830a3)
}

func encode(hrp string, ver, in []byte, constant uint32) (string, error) {
	if len(hrp) < minHrpLen || len(hrp) > maxHrpLen {
		return "", InvalidHrpLengthError{Length: len(hrp)}
	}
	for i := range len(hrp) {
		if hrp[i] < minHrpChar || hrp[i] > maxHrpChar {
			return "", InvalidHrpCharError{Offset: i, Char: hrp[i]}
		}
	}
	for i := range ver {
		if ver[i] > maxVerByte {
			return "", InvalidVerByteError{Offset: i, Byte: ver[i]}
		}
	}
	verin, remain, shift := bytes.Clone(ver), uint32(0), 0
	for i := range in {
		remain, shift = (remain<<8)|uint32(in[i]), shift+8
		for shift >= 5 {
			shift -= 5
			verin = append(verin, byte(remain>>shift))
			remain &= (1 << shift) - 1
		}
	}
	if shift > 0 {
		verin = append(verin, byte(remain<<(5-shift)))
	}
	out := make([]byte, 0, len(hrp)+1+len(verin)+6)
	out = append(out, hrp...)
	out = append(out, '1')
	for i := range verin {
		out = append(out, alphabet[verin[i]])
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
	for i := range verin {
		iterate(uint32(verin[i]))
	}
	for range 6 {
		iterate(0)
	}
	polymod ^= constant
	for i := range 6 {
		out = append(out, alphabet[(polymod>>(25-5*i))&31])
	}
	return string(out), nil
}
