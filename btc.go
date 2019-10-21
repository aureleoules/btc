package btc

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"

	"github.com/aureleoules/ecdsa"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ripemd160"
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

// GetPublicKey returns the public key of a private key
func (p *PrivateKey) GetPublicKey() (*PublicKey, bool) {
	var publicKey PublicKey

	R, valid := secp256k1.ScalarMult(p.Key, secp256k1.G)
	if !valid {
		return nil, false
	}
	publicKey.X = R.X
	publicKey.Y = R.Y

	return &publicKey, true
}

// Hex returns the public key in hex
func (p *PublicKey) Hex(compressed bool) string {
	key := ""
	if !compressed {
		key += "04"

		key += bigIntToHex(p.X)
		key += bigIntToHex(p.Y)
	} else {
		if p.Y.Bit(0) == 0 { /* Even */
			key += "02"
		} else {
			key += "03"
		}
		key += bigIntToHex(p.X)
	}
	return key
}

// Address computes the base58 public address
func (p *PublicKey) Address(compressed bool, networkByte string) (string, error) {
	hexa := p.Hex(compressed)
	bytes, err := hex.DecodeString(hexa)
	if err != nil {
		return "", err
	}

	/* First sha256 hashing */
	sha := sha256.New()
	sha.Write(bytes)
	/* Store it in hash */
	hash := sha.Sum(nil)

	/* Ripemd hash of the sha256 hash */
	ripemd := ripemd160.New()
	ripemd.Write(hash)
	/* Store it in ripemdHash */
	ripemdHash := ripemd.Sum(nil)

	/* Convert ripemdHash to hex */
	hexa = hex.EncodeToString(ripemdHash)
	/* Add network byte */
	extendedRipemd := networkByte + hexa

	/* Perform sha256 hash on the ripemdHash with the network byte */
	bytes, err = hex.DecodeString(extendedRipemd)
	if err != nil {
		return "", err
	}
	sha = sha256.New()
	sha.Write(bytes)
	/* Store it in hash */
	hash = sha.Sum(nil)

	/* Perform another sha256 hash on the previous sha256 hash */
	sha = sha256.New()
	sha.Write(hash)
	/* Store it in hash */
	hash = sha.Sum(nil)

	/* Convert double hash to hex */
	hexa = hex.EncodeToString(hash)

	/* Get checksum (4 first bytes of double hash) */
	checksum := hexa[0:8]

	/* Add to end of extendedRipemd*/
	extendedRipemd += checksum

	/* Convert to []byte */
	extendedRipeMd, err := hex.DecodeString(extendedRipemd)
	if err != nil {
		return "", err
	}

	/* Encode to base 58 */
	return base58.Encode(extendedRipeMd), nil
}
