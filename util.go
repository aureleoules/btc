package btc

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

func generateRandomBigInt() *big.Int {
	max, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)

	nBig, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(err)
	}
	return nBig
}

func bigIntToHex(n *big.Int) string {
	return fmt.Sprintf("%x", n)
}
