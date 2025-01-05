package bip3x_test

import (
	"encoding/hex"
	"testing"

	"github.com/rbee3u/dpass/pkg/bip3x"
)

func TestSecp256k1DeriveSk(t *testing.T) {
	tests := []struct {
		seed string
		path []uint32
		sk0x string
	}{
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{},
			sk0x: "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild},
			sk0x: "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1},
			sk0x: "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1, 2 + bip3x.FirstHardenedChild},
			sk0x: "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1, 2 + bip3x.FirstHardenedChild, 2},
			sk0x: "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1, 2 + bip3x.FirstHardenedChild, 2, 1000000000},
			sk0x: "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{},
			sk0x: "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0},
			sk0x: "abe74a98f6c7eabee0428f53798f0ab8aa1bd37873999041703c742f15ac7e1e",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0, 2147483647 + bip3x.FirstHardenedChild},
			sk0x: "877c779ad9687164e9c2f4f0f4ff0340814392330693ce95a58fe18fd52e6e93",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0, 2147483647 + bip3x.FirstHardenedChild, 1},
			sk0x: "704addf544a06e5ee4bea37098463c23613da32020d604506da8c0518e1da4b7",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0, 2147483647 + bip3x.FirstHardenedChild, 1, 2147483646 + bip3x.FirstHardenedChild},
			sk0x: "f1c7c871a54a804afe328b4c83a1c33b8e5ff48f5087273f04efa83b247d6a2d",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0, 2147483647 + bip3x.FirstHardenedChild, 1, 2147483646 + bip3x.FirstHardenedChild, 2},
			sk0x: "bb7d39bdb83ecf58f2fd82b6d918341cbef428661ef01ab97c28a4842125ac23",
		},
		{
			seed: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
			path: []uint32{},
			sk0x: "00ddb80b067e0d4993197fe10f2657a844a384589847602d56f0c629c81aae32",
		},
		{
			seed: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
			path: []uint32{0 + bip3x.FirstHardenedChild},
			sk0x: "491f7a2eebc7b57028e0d3faa0acda02e75c33b03c48fb288c41e2ea44e1daef",
		},
		{
			seed: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
			path: []uint32{},
			sk0x: "12c0d59c7aa3a10973dbd3f478b65f2516627e3fe61e00c345be9a477ad2e215",
		},
		{
			seed: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
			path: []uint32{0 + bip3x.FirstHardenedChild},
			sk0x: "00d948e9261e41362a688b916f297121ba6bfb2274a3575ac0e456551dfd7f7e",
		},
		{
			seed: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild},
			sk0x: "3a2086edd7d9df86c3487a5905a1712a9aa664bce8cc268141e07549eaa8661d",
		},
	}
	for _, tt := range tests {
		seed, err := hex.DecodeString(tt.seed)
		if err != nil {
			t.Fatalf("failed to decode seed: %v", err)
		}
		sk, err := bip3x.Secp256k1DeriveSk(seed, tt.path)
		if err != nil {
			t.Fatalf("failed to derive sk: %v", err)
		}
		if sk0x := hex.EncodeToString(sk); sk0x != tt.sk0x {
			t.Errorf("got = %s, want = %s", sk0x, tt.sk0x)
		}
	}
}

func TestEd25519DeriveSk(t *testing.T) {
	tests := []struct {
		seed string
		path []uint32
		sk0x string
	}{
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{},
			sk0x: "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild},
			sk0x: "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild},
			sk0x: "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild, 2 + bip3x.FirstHardenedChild},
			sk0x: "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild, 2 + bip3x.FirstHardenedChild, 2 + bip3x.FirstHardenedChild},
			sk0x: "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662",
		},
		{
			seed: "000102030405060708090a0b0c0d0e0f",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild, 2 + bip3x.FirstHardenedChild, 2 + bip3x.FirstHardenedChild, 1000000000 + bip3x.FirstHardenedChild},
			sk0x: "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{},
			sk0x: "171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0 + bip3x.FirstHardenedChild},
			sk0x: "1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0 + bip3x.FirstHardenedChild, 2147483647 + bip3x.FirstHardenedChild},
			sk0x: "ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0 + bip3x.FirstHardenedChild, 2147483647 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild},
			sk0x: "3757c7577170179c7868353ada796c839135b3d30554bbb74a4b1e4a5a58505c",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0 + bip3x.FirstHardenedChild, 2147483647 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild, 2147483646 + bip3x.FirstHardenedChild},
			sk0x: "5837736c89570de861ebc173b1086da4f505d4adb387c6a1b1342d5e4ac9ec72",
		},
		{
			seed: "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
			path: []uint32{0 + bip3x.FirstHardenedChild, 2147483647 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild, 2147483646 + bip3x.FirstHardenedChild, 2 + bip3x.FirstHardenedChild},
			sk0x: "551d333177df541ad876a60ea71f00447931c0a9da16f227c11ea080d7391b8d",
		},
		{
			seed: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
			path: []uint32{},
			sk0x: "93617e77ebf8d931440dbcbfdf3f22ef1fdd1c393984e5f8f7f95b8591a9262c",
		},
		{
			seed: "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
			path: []uint32{0 + bip3x.FirstHardenedChild},
			sk0x: "8385d6cac2ad13082160a0f16ffcf8c51f3e27fad7e0a8cada2cee1fdb5cb368",
		},
		{
			seed: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
			path: []uint32{},
			sk0x: "4b36bc63a15797f4d506074f36f2f3904bc0f10179b5ab91183c167e9c2dcf0e",
		},
		{
			seed: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
			path: []uint32{0 + bip3x.FirstHardenedChild},
			sk0x: "0b87dbaac2fb145db595ebe0bc4ddd4be2276197cb1da250ab9640bc3d651eb8",
		},
		{
			seed: "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
			path: []uint32{0 + bip3x.FirstHardenedChild, 1 + bip3x.FirstHardenedChild},
			sk0x: "ae20173bb3d7e58033a40ae668634d0bebae98d5f95d2cea6a89a7a22302de0d",
		},
	}
	for _, tt := range tests {
		seed, err := hex.DecodeString(tt.seed)
		if err != nil {
			t.Fatalf("failed to decode seed: %v", err)
		}
		sk, err := bip3x.Ed25519DeriveSk(seed, tt.path)
		if err != nil {
			t.Fatalf("failed to derive sk: %v", err)
		}
		if sk0x := hex.EncodeToString(sk); sk0x != tt.sk0x {
			t.Errorf("got = %s, want = %s", sk0x, tt.sk0x)
		}
	}
}
