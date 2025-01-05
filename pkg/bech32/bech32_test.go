package bech32_test

import (
	"encoding/hex"
	"testing"

	"github.com/rbee3u/dpass/pkg/bech32"
)

func TestEncode(t *testing.T) {
	tests := []struct {
		hrp  string
		vs0x string
		in0x string
		out  string
	}{
		{
			hrp:  "bc",
			vs0x: "00",
			in0x: "751e76e8199196d454941c45d1b3a323f1433bd6",
			out:  "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
		},
		{
			hrp:  "tb",
			vs0x: "00",
			in0x: "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
			out:  "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
		},
		{
			hrp:  "bc",
			vs0x: "01",
			in0x: "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6",
			out:  "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
		},
		{
			hrp:  "bc",
			vs0x: "10",
			in0x: "751e",
			out:  "bc1sw50qa3jx3s",
		},
		{
			hrp:  "bc",
			vs0x: "02",
			in0x: "751e76e8199196d454941c45d1b3a323",
			out:  "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
		},
		{
			hrp:  "tb",
			vs0x: "00",
			in0x: "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433",
			out:  "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
		},
	}
	for _, tt := range tests {
		vs, err := hex.DecodeString(tt.vs0x)
		if err != nil {
			t.Fatalf("failed to decode vs: %v", err)
		}
		in, err := hex.DecodeString(tt.in0x)
		if err != nil {
			t.Fatalf("failed to decode in: %v", err)
		}
		out := bech32.Encode(tt.hrp, vs, in)
		if out != tt.out {
			t.Errorf("got = %s, want = %s", out, tt.out)
		}
	}
}
