package secp256k1_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/rbee3u/dpass/pkg/secp256k1"
)

func TestS256(t *testing.T) {
	curve := secp256k1.S256()

	require.Same(t, curve, secp256k1.S256())
	require.Equal(t, "secp256k1", curve.Name)
	require.Equal(t, 256, curve.BitSize)
	require.True(t, curve.IsOnCurve(curve.Gx, curve.Gy))
}

func TestIsOnCurve(t *testing.T) {
	curve := secp256k1.S256()

	tests := []struct {
		name string
		x    *big.Int
		y    *big.Int
		want bool
	}{
		{
			name: "generator",
			x:    new(big.Int).Set(curve.Gx),
			y:    new(big.Int).Set(curve.Gy),
			want: true,
		},
		{
			name: "point at infinity sentinel",
			x:    big.NewInt(0),
			y:    big.NewInt(0),
			want: false,
		},
		{
			name: "negative x",
			x:    big.NewInt(-1),
			y:    new(big.Int).Set(curve.Gy),
			want: false,
		},
		{
			name: "x equals field modulus",
			x:    new(big.Int).Set(curve.P),
			y:    new(big.Int).Set(curve.Gy),
			want: false,
		},
		{
			name: "y equals field modulus",
			x:    new(big.Int).Set(curve.Gx),
			y:    new(big.Int).Set(curve.P),
			want: false,
		},
		{
			name: "mismatched y coordinate",
			x:    new(big.Int).Set(curve.Gx),
			y:    new(big.Int).Add(curve.Gy, big.NewInt(1)),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, curve.IsOnCurve(tt.x, tt.y))
		})
	}
}

func TestAdd(t *testing.T) {
	curve := secp256k1.S256()
	twoGX := mustHex(t, "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5")
	twoGY := mustHex(t, "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A")

	tests := []struct {
		name   string
		x1, y1 *big.Int
		x2, y2 *big.Int
		wantX  *big.Int
		wantY  *big.Int
	}{
		{
			name:  "left infinity is identity",
			x1:    big.NewInt(0),
			y1:    big.NewInt(0),
			x2:    new(big.Int).Set(curve.Gx),
			y2:    new(big.Int).Set(curve.Gy),
			wantX: curve.Gx,
			wantY: curve.Gy,
		},
		{
			name:  "right infinity is identity",
			x1:    new(big.Int).Set(curve.Gx),
			y1:    new(big.Int).Set(curve.Gy),
			x2:    big.NewInt(0),
			y2:    big.NewInt(0),
			wantX: curve.Gx,
			wantY: curve.Gy,
		},
		{
			name:  "inverse points cancel to infinity",
			x1:    new(big.Int).Set(curve.Gx),
			y1:    new(big.Int).Set(curve.Gy),
			x2:    new(big.Int).Set(curve.Gx),
			y2:    negateY(curve, curve.Gy),
			wantX: big.NewInt(0),
			wantY: big.NewInt(0),
		},
		{
			name:  "generator plus generator",
			x1:    new(big.Int).Set(curve.Gx),
			y1:    new(big.Int).Set(curve.Gy),
			x2:    new(big.Int).Set(curve.Gx),
			y2:    new(big.Int).Set(curve.Gy),
			wantX: twoGX,
			wantY: twoGY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotX, gotY := curve.Add(tt.x1, tt.y1, tt.x2, tt.y2)
			requirePointEqual(t, tt.wantX, tt.wantY, gotX, gotY)
		})
	}
}

func TestAddPanicsOnInvalidPoint(t *testing.T) {
	curve := secp256k1.S256()
	invalidX := big.NewInt(1)
	invalidY := big.NewInt(1)

	require.False(t, curve.IsOnCurve(invalidX, invalidY))

	tests := []struct {
		name    string
		wantErr string
		call    func()
	}{
		{
			name:    "invalid first point",
			wantErr: "attempted operation on invalid point(x1, y1)",
			call: func() {
				curve.Add(invalidX, invalidY, curve.Gx, curve.Gy)
			},
		},
		{
			name:    "invalid second point",
			wantErr: "attempted operation on invalid point(x2, y2)",
			call: func() {
				curve.Add(curve.Gx, curve.Gy, invalidX, invalidY)
			},
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

	x, y := curve.Double(curve.Gx, curve.Gy)
	requirePointEqual(
		t,
		mustHex(t, "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"),
		mustHex(t, "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
		x,
		y,
	)

	x, y = curve.Double(big.NewInt(0), big.NewInt(0))
	requirePointEqual(t, big.NewInt(0), big.NewInt(0), x, y)
}

func TestScalarMult(t *testing.T) {
	curve := secp256k1.S256()

	tests := []struct {
		name   string
		scalar []byte
		wantX  *big.Int
		wantY  *big.Int
	}{
		{
			name:   "zero scalar",
			scalar: []byte{0x00},
			wantX:  big.NewInt(0),
			wantY:  big.NewInt(0),
		},
		{
			name:   "one scalar",
			scalar: []byte{0x01},
			wantX:  curve.Gx,
			wantY:  curve.Gy,
		},
		{
			name:   "two scalar",
			scalar: []byte{0x02},
			wantX:  mustHex(t, "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5"),
			wantY:  mustHex(t, "1AE168FEA63DC339A3C58419466CEAEEF7F632653266D0E1236431A950CFE52A"),
		},
		{
			name:   "three scalar",
			scalar: []byte{0x03},
			wantX:  mustHex(t, "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
			wantY:  mustHex(t, "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
		},
		{
			name:   "leading zero scalar",
			scalar: []byte{0x00, 0x03},
			wantX:  mustHex(t, "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
			wantY:  mustHex(t, "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotX, gotY := curve.ScalarMult(curve.Gx, curve.Gy, tt.scalar)
			requirePointEqual(t, tt.wantX, tt.wantY, gotX, gotY)
		})
	}
}

func TestScalarBaseMult(t *testing.T) {
	curve := secp256k1.S256()

	tests := []struct {
		name   string
		scalar []byte
		wantX  *big.Int
		wantY  *big.Int
	}{
		{
			name:   "zero scalar",
			scalar: []byte{0x00},
			wantX:  big.NewInt(0),
			wantY:  big.NewInt(0),
		},
		{
			name:   "three scalar",
			scalar: []byte{0x03},
			wantX:  mustHex(t, "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9"),
			wantY:  mustHex(t, "388F7B0F632DE8140FE337E62A37F3566500A99934C2231B6CB9FD7584B8E672"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotX, gotY := curve.ScalarBaseMult(tt.scalar)
			requirePointEqual(t, tt.wantX, tt.wantY, gotX, gotY)
		})
	}
}

func mustHex(t *testing.T, s string) *big.Int {
	t.Helper()

	n, ok := new(big.Int).SetString(s, 16)
	require.True(t, ok)

	return n
}

func negateY(curve *secp256k1.Curve, y *big.Int) *big.Int {
	neg := new(big.Int).Sub(curve.P, y)
	neg.Mod(neg, curve.P)

	return neg
}

func requirePointEqual(t *testing.T, wantX, wantY, gotX, gotY *big.Int) {
	t.Helper()

	require.Zero(t, wantX.Cmp(gotX))
	require.Zero(t, wantY.Cmp(gotY))
	if wantX.Sign() != 0 || wantY.Sign() != 0 {
		require.True(t, secp256k1.S256().IsOnCurve(gotX, gotY))
	}
}
