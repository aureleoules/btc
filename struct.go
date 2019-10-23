package btc

import (
	"math/big"
)

// Network struct
type Network struct {
	PrivKeyPrefix    string
	PubKeyHashPrefix string
}

// PrivateKey struct
type PrivateKey struct {
	Key *big.Int
	Hex string
	WIF string

	Network *Network
}

// PublicKey struct
type PublicKey struct {
	X *big.Int
	Y *big.Int

	Network *Network
}
