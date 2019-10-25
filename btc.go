package btc

import (
	"math/big"

	"github.com/aureleoules/ecdsa"
)

var secp256k1 ecdsa.Curve

// MainNetwork contains mainnet parameters
var MainNetwork *Network

// TestNetwork contains testnet parameters
var TestNetwork *Network

func init() {
	secp256k1.A, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	secp256k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)

	secp256k1.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secp256k1.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	secp256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1.H, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000001", 16)

	MainNetwork = &Network{
		PrivKeyPrefix:    "80",
		PubKeyHashPrefix: "00",
	}

	TestNetwork = &Network{
		PrivKeyPrefix:    "EF",
		PubKeyHashPrefix: "6F",
	}
}
