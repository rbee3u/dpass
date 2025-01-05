package bech32

import (
	"bytes"
)

const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

func Encode(hrp string, vs, in []byte) string {
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
	))
}
