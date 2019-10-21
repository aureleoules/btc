package btc

import (
	"math/big"
)

// PrivateKey struct
type PrivateKey struct {
	Key *big.Int
	Hex string
	WIF string
}

// PublicKey struct
type PublicKey struct {
	X *big.Int
	Y *big.Int
}
