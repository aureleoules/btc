package btc

import (
	"log"
	"math/big"
)

// PrivateKey struct
type PrivateKey struct {
	Key *big.Int
	Hex string
	WIF string
}

// GetPublicAddress returns public address of private key
func (p *PrivateKey) GetPublicAddress() (string, bool) {
	log.Println(p.Key)
	R, valid := secp256k1.ScalarMult(p.Key, secp256k1.G)
	if !valid {
		return "", false
	}

	hexa := bigIntToHex(R.X)

	log.Println("WIF", p.WIF)
	log.Println("HEX", hexa)
	log.Println("KEY", R.X, R.Y)
	return "", true
}
