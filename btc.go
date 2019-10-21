package btc

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/aureleoules/ecdsa"
	"github.com/mr-tron/base58"
)

var secp256k1 ecdsa.Curve
var networkByte string

func init() {
	secp256k1.A, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000000", 16)
	secp256k1.B, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000007", 16)

	secp256k1.G.X, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	secp256k1.G.Y, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	secp256k1.P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	secp256k1.N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	secp256k1.H, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000001", 16)
}

// SetNetworkByte sets the correct Bitcoin network (80 = mainnet; EF = testnet)
func SetNetworkByte(hexByte string) {
	networkByte = hexByte
}

// GeneratePrivateKey returns a PrivateKey
func GeneratePrivateKey() *PrivateKey {

	var privateKey PrivateKey

	/* Generate a number between 1 and 2^256 */
	key := generateRandomBigInt()
	privateKey.Key = key
	hexa := bigIntToHex(key)
	privateKey.Hex = hexa
	/* Add network byte to the hex value */
	hexa = networkByte + hexa
	/* Convert to []byte */
	hexaB, err := hex.DecodeString(hexa)
	if err != nil {
		/* Retry */
		return GeneratePrivateKey()
	}
	/* Compute first hash */
	sha := sha256.New()

	sha.Write(hexaB)
	hash := sha.Sum(nil)

	/* Compute double hash */
	sha = sha256.New()
	sha.Write(hash)
	doubleHashHex := sha.Sum(nil)

	/* Convert to hex */
	checksum := hex.EncodeToString(doubleHashHex)
	/* Only take the first 4 bytes */
	checksum = checksum[0:8]

	/* Concat checksum to hexa */
	hexa += checksum

	hexaB, err = hex.DecodeString(hexa)
	if err != nil {
		/* Retry */
		return GeneratePrivateKey()
	}

	wif := base58.Encode(hexaB)

	privateKey.WIF = wif
	return &privateKey
}
