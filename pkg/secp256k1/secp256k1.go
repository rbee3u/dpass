package secp256k1

import (
	"crypto/elliptic"
	"math/big"
)

type Curve struct{ *elliptic.CurveParams }

func (curve *Curve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(curve.P) >= 0 || y.Sign() < 0 || y.Cmp(curve.P) >= 0 {
		return false
	}
	xPart := new(big.Int).Mul(x, x)
	xPart.Mul(xPart, x)
	xPart.Add(xPart, curve.B)
	xPart.Mod(xPart, curve.P)
	yPart := new(big.Int).Mul(y, y)
	yPart.Mod(yPart, curve.P)
	return xPart.Cmp(yPart) == 0 // check if `x`, `y` satisfy `x^3 + b = y^2 (mod p)`
}

func (curve *Curve) Add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if (x1.Sign() != 0 || y1.Sign() != 0) && !curve.IsOnCurve(x1, y1) {
		panic("attempted operation on invalid point(x1, y1)")
	}
	if (x2.Sign() != 0 || y2.Sign() != 0) && !curve.IsOnCurve(x2, y2) {
		panic("attempted operation on invalid point(x2, y2)")
	}
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}
	var n, d *big.Int
	if x1.Cmp(x2) == 0 {
		y3 := new(big.Int).Add(y1, y2)
		y3.Mod(y3, curve.P)
		if y3.Sign() == 0 {
			return big.NewInt(0), big.NewInt(0)
		}
		n = big.NewInt(3)
		n.Mul(n, x1)
		n.Mul(n, x1)
		d = big.NewInt(2)
		d.Mul(d, y1)
	} else {
		n = new(big.Int).Sub(y1, y2)
		d = new(big.Int).Sub(x1, x2)
	}
	n.Mod(n, curve.P)
	d.Mod(d, curve.P)
	d.ModInverse(d, curve.P)
	m := new(big.Int).Mul(n, d)
	m.Mod(m, curve.P)
	x3 := new(big.Int).Mul(m, m)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, curve.P)
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, m)
	y3.Sub(y3, y1)
	y3.Mod(y3, curve.P)
	return x3, y3
}

func (curve *Curve) Double(x1, y1 *big.Int) (*big.Int, *big.Int) {
	return curve.Add(x1, y1, x1, y1)
}

func (curve *Curve) ScalarMult(x1, y1 *big.Int, k []byte) (*big.Int, *big.Int) {
	x, y := new(big.Int), new(big.Int)
	for _, b := range k {
		for i := 7; i >= 0; i-- {
			x, y = curve.Double(x, y)
			if b&(1<<i) != 0 {
				x, y = curve.Add(x, y, x1, y1)
			}
		}
	}
	return x, y
}

func (curve *Curve) ScalarBaseMult(k []byte) (*big.Int, *big.Int) {
	return curve.ScalarMult(curve.Gx, curve.Gy, k)
}

func S256() *Curve { return s256 }

var s256 = &Curve{CurveParams: &elliptic.CurveParams{
	Name: "secp256k1", BitSize: 256,
	P:  convertHexToBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"),
	N:  convertHexToBig("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"),
	B:  convertHexToBig("0000000000000000000000000000000000000000000000000000000000000007"),
	Gx: convertHexToBig("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
	Gy: convertHexToBig("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
}}

func convertHexToBig(s string) *big.Int {
	b, _ := new(big.Int).SetString(s, 16)
	if b == nil {
		panic("secp256k1: s is invalid")
	}
	return b
}
