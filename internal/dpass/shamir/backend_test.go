package shamir

import (
	"bytes"
	"encoding/pem"
	"testing"
)

func TestSplitBackend(t *testing.T) {
	secret := []byte("To be, or not to be, that is the question.")
	sb := splitBackendDefault()
	sb.parts = 9
	sb.threshold = 4
	blocks, err := sb.split(secret)
	if err != nil {
		t.Fatalf("failed to split: %v", err)
	}
	for _, group := range groups94(blocks) {
		cb := combineBackendDefault()
		combinedSecret, err := cb.combine(group)
		if err != nil {
			t.Fatalf("failed to combine: %v", err)
		}
		if !bytes.Equal(combinedSecret, secret) {
			t.Fatalf("got = %v, want = %v", combinedSecret, secret)
		}
	}
}

func TestCombineBackend(t *testing.T) {
	secret := []byte("To be, or not to be, that is the question.")
	blocks := make([]*pem.Block, 9)
	blocks[0], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 0
M: 4
N: 9

Dk3CZ2JyqWolAndv6mR/3wKTfV8DyZklxG6DhbVMCxNHy1mF2Zc2OUkIqg==
-----END SHAMIR-----
`))
	blocks[1], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 1
M: 4
N: 9

Smmg52twM1VredYIRNZV6zi//2ker0aPVodffiH41n1/u8bY65Y7u60xag==
-----END SHAMIR-----
`))
	blocks[2], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 2
M: 4
N: 9

YMbVk0audTbtH6LMlowsKBGSRp+ZnHFhDEg/vFcH5lWHOMtGJErR/kT5zA==
-----END SHAMIR-----
`))
	blocks[3], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 3
M: 4
N: 9

hbjVzD0jh0XEENKPOu4bkeAqjUHgK4SJWqETXVN08L8K1/VbRYIqapnVjA==
-----END SHAMIR-----
`))
	blocks[4], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 4
M: 4
N: 9

FaaWqcffvsZqyYMEIRO62xDetR4+ZsnHRzOMlNIYXCQ81YQvj9OzPWv3OA==
-----END SHAMIR-----
`))
	blocks[5], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 5
M: 4
N: 9

K1T5ZHs4Id9DUU6Y2CSUHZdScPe+y4xKbMvJLpizUVuthpMOF0aZTQNgIw==
-----END SHAMIR-----
`))
	blocks[6], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 6
M: 4
N: 9

vRDD4CSccI84z02dublRBZUsNLQ46w+H6hYIMMSHsd3Po1NVb3NHk9Ft5A==
-----END SHAMIR-----
`))
	blocks[7], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 7
M: 4
N: 9

Zfev+F6BGDQSaSFoQiP48o+8DsVZV64eX0ceQzqmcJouqbGaajchgmMEuQ==
-----END SHAMIR-----
`))
	blocks[8], _ = pem.Decode([]byte(`
-----BEGIN SHAMIR-----
I: 8
M: 4
N: 9

1N3xLp2dDR1NlNvVSUPBht5Z/UYtu5ZhtOrvzc+ljz1a7VorCwfCZ7b3EQ==
-----END SHAMIR-----
`))
	for _, group := range groups94(blocks) {
		cb := combineBackendDefault()
		combinedSecret, err := cb.combine(group)
		if err != nil {
			t.Fatalf("failed to combine: %v", err)
		}
		if !bytes.Equal(combinedSecret, secret) {
			t.Fatalf("got = %v, want = %v", combinedSecret, secret)
		}
	}
}

func groups94(blocks []*pem.Block) [][]*pem.Block {
	var groups [][]*pem.Block
	for a := 0; a < 9; a++ {
		for b := 0; b < a; b++ {
			for c := 0; c < b; c++ {
				for d := 0; d < c; d++ {
					groups = append(groups, []*pem.Block{
						blocks[a], blocks[b], blocks[c], blocks[d],
					})
				}
			}
		}
	}
	return groups
}
