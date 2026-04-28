package secp256k1_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/secp256k1"
)

func TestS256(t *testing.T) {
	curve := secp256k1.S256()
	require.Same(t, secp256k1.S256(), curve)
	require.Equal(t, "secp256k1", curve.Name)
	require.Equal(t, 256, curve.BitSize)
	require.True(t, curve.IsOnCurve(curve.Gx, curve.Gy))
}

func TestIsOnCurve(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name    string
		x       *big.Int
		y       *big.Int
		onCurve bool
	}{
		{
			name:    "generator",
			x:       new(big.Int).Set(curve.Gx),
			y:       new(big.Int).Set(curve.Gy),
			onCurve: true,
		},
		{
			name:    "point at infinity sentinel",
			x:       big.NewInt(0),
			y:       big.NewInt(0),
			onCurve: false,
		},
		{
			name:    "negative x",
			x:       big.NewInt(-1),
			y:       new(big.Int).Set(curve.Gy),
			onCurve: false,
		},
		{
			name:    "x equals field modulus",
			x:       new(big.Int).Set(curve.P),
			y:       new(big.Int).Set(curve.Gy),
			onCurve: false,
		},
		{
			name:    "negative y",
			x:       new(big.Int).Set(curve.Gx),
			y:       big.NewInt(-1),
			onCurve: false,
		},
		{
			name:    "y equals field modulus",
			x:       new(big.Int).Set(curve.Gx),
			y:       new(big.Int).Set(curve.P),
			onCurve: false,
		},
		{
			name:    "mismatched y coordinate",
			x:       new(big.Int).Set(curve.Gx),
			y:       new(big.Int).Add(curve.Gy, big.NewInt(1)),
			onCurve: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.onCurve, curve.IsOnCurve(tt.x, tt.y))
		})
	}
}

func TestAdd(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name   string
		x1, y1 *big.Int
		x2, y2 *big.Int
		x3, y3 *big.Int
	}{
		{
			name: "left infinity is identity",
			x1:   big.NewInt(0),
			y1:   big.NewInt(0),
			x2:   new(big.Int).Set(curve.Gx),
			y2:   new(big.Int).Set(curve.Gy),
			x3:   curve.Gx,
			y3:   curve.Gy,
		},
		{
			name: "right infinity is identity",
			x1:   new(big.Int).Set(curve.Gx),
			y1:   new(big.Int).Set(curve.Gy),
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
			x3:   curve.Gx,
			y3:   curve.Gy,
		},
		{
			name: "inverse points cancel to infinity",
			x1:   new(big.Int).Set(curve.Gx),
			y1:   new(big.Int).Set(curve.Gy),
			x2:   new(big.Int).Set(curve.Gx),
			y2:   mustHex(t, "b7c52588d95c3b9aa25b0403f1eef75702e84bb7597aabe663b82f6f04ef2777"),
			x3:   big.NewInt(0),
			y3:   big.NewInt(0),
		},
		{
			name: "generator plus generator",
			x1:   new(big.Int).Set(curve.Gx),
			y1:   new(big.Int).Set(curve.Gy),
			x2:   new(big.Int).Set(curve.Gx),
			y2:   new(big.Int).Set(curve.Gy),
			x3:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y3:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x3, y3 := curve.Add(tt.x1, tt.y1, tt.x2, tt.y2)
			requirePointEqual(t, tt.x3, tt.y3, x3, y3)
		})
	}
}

func TestAddErrors(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name    string
		wantErr string
		call    func()
	}{
		{
			name:    "invalid first point",
			wantErr: "secp256k1: attempted operation on invalid point(x1, y1)",
			call:    func() { curve.Add(big.NewInt(1), big.NewInt(1), curve.Gx, curve.Gy) },
		},
		{
			name:    "invalid second point",
			wantErr: "secp256k1: attempted operation on invalid point(x2, y2)",
			call:    func() { curve.Add(curve.Gx, curve.Gy, big.NewInt(1), big.NewInt(1)) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.PanicsWithValue(t, tt.wantErr, tt.call)
		})
	}
}

func TestDouble(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name   string
		x1, y1 *big.Int
		x2, y2 *big.Int
	}{
		{
			name: "generator doubles to 2G",
			x1:   new(big.Int).Set(curve.Gx),
			y1:   new(big.Int).Set(curve.Gy),
			x2:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y2:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
		},
		{
			name: "infinity doubles to infinity",
			x1:   big.NewInt(0),
			y1:   big.NewInt(0),
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x2, y2 := curve.Double(tt.x1, tt.y1)
			requirePointEqual(t, tt.x2, tt.y2, x2, y2)
		})
	}
}

func TestDoubleErrors(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name    string
		wantErr string
		call    func()
	}{
		{
			name:    "invalid point",
			wantErr: "secp256k1: attempted operation on invalid point(x1, y1)",
			call:    func() { curve.Double(big.NewInt(1), big.NewInt(1)) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.PanicsWithValue(t, tt.wantErr, tt.call)
		})
	}
}

func TestScalarMult(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name   string
		x1, y1 *big.Int
		k      []byte
		x2, y2 *big.Int
	}{
		{
			name: "nil scalar",
			x1:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y1:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			k:    nil,
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
		},
		{
			name: "empty scalar",
			x1:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y1:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			k:    []byte{},
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
		},
		{
			name: "zero scalar",
			x1:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y1:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			k:    []byte{0x0},
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
		},
		{
			name: "one scalar",
			x1:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y1:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			k:    []byte{0x1},
			x2:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y2:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
		},
		{
			name: "two scalar",
			x1:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y1:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			k:    []byte{0x2},
			x2:   mustHex(t, "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"),
			y2:   mustHex(t, "51ed993ea0d455b75642e2098ea51448d967ae33bfbdfe40cfe97bdc47739922"),
		},
		{
			name: "three scalar",
			x1:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y1:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			k:    []byte{0x3},
			x2:   mustHex(t, "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"),
			y2:   mustHex(t, "ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297"),
		},
		{
			name: "leading zero scalar",
			x1:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y1:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
			k:    []byte{0x0, 0x3},
			x2:   mustHex(t, "fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556"),
			y2:   mustHex(t, "ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x2, y2 := curve.ScalarMult(tt.x1, tt.y1, tt.k)
			requirePointEqual(t, tt.x2, tt.y2, x2, y2)
		})
	}
}

func TestScalarMultErrors(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name    string
		wantErr string
		call    func()
	}{
		{
			name:    "invalid point",
			wantErr: "secp256k1: attempted operation on invalid point(x2, y2)",
			call:    func() { curve.ScalarMult(big.NewInt(1), big.NewInt(1), []byte{0x1}) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.PanicsWithValue(t, tt.wantErr, tt.call)
		})
	}
}

func TestScalarBaseMult(t *testing.T) {
	curve := secp256k1.S256()
	tests := []struct {
		name   string
		k      []byte
		x2, y2 *big.Int
	}{
		{
			name: "nil scalar",
			k:    nil,
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
		},
		{
			name: "empty scalar",
			k:    []byte{},
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
		},
		{
			name: "zero scalar",
			k:    []byte{0x0},
			x2:   big.NewInt(0),
			y2:   big.NewInt(0),
		},
		{
			name: "one scalar",
			k:    []byte{0x1},
			x2:   mustHex(t, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
			y2:   mustHex(t, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
		},
		{
			name: "two scalar",
			k:    []byte{0x2},
			x2:   mustHex(t, "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"),
			y2:   mustHex(t, "1ae168fea63dc339a3c58419466ceaeef7f632653266d0e1236431a950cfe52a"),
		},
		{
			name: "three scalar",
			k:    []byte{0x03},
			x2:   mustHex(t, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
			y2:   mustHex(t, "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
		},
		{
			name: "leading zero scalar",
			k:    []byte{0x0, 0x3},
			x2:   mustHex(t, "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
			y2:   mustHex(t, "388f7b0f632de8140fe337e62a37f3566500a99934c2231b6cb9fd7584b8e672"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x2, y2 := curve.ScalarBaseMult(tt.k)
			requirePointEqual(t, tt.x2, tt.y2, x2, y2)
		})
	}
}

func mustHex(t *testing.T, s string) *big.Int {
	t.Helper()
	b, _ := new(big.Int).SetString(s, 16)
	require.NotNil(t, b)
	return b
}

func requirePointEqual(t *testing.T, wantX, wantY, gotX, gotY *big.Int) {
	t.Helper()
	require.Equal(t,
		fmt.Sprintf("(0x%s, 0x%s)", wantX.Text(16), wantY.Text(16)),
		fmt.Sprintf("(0x%s, 0x%s)", gotX.Text(16), gotY.Text(16)),
	)
}
