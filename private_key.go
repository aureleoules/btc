package btc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/mr-tron/base58"
)

// CheckWIF checks if the wif checksum is valid
func CheckWIF(wif string) bool {
	bytes, err := base58.Decode(wif)
	if err != nil {
		return false
	}

	hexa := hex.EncodeToString(bytes)
	checksum := hexa[len(hexa)-8 : len(hexa)]
	hexa = hexa[0 : len(hexa)-8]

	hexBytes, err := hex.DecodeString(hexa)
	if err != nil {
		return false
	}

	sha := sha256.New()
	sha.Write(hexBytes)
	hash := sha.Sum(nil)

	sha = sha256.New()
	sha.Write(hash)
	hash2 := sha.Sum(nil)

	hash2Hex := hex.EncodeToString(hash2)

	return hash2Hex[0:8] == checksum
}

// PrivateFromWIF imports a private key from its base58 address
func PrivateFromWIF(wif string, network *Network) (*PrivateKey, error) {

	valid := CheckWIF(wif)
	if !valid {
		return nil, errors.New("wif invalid")
	}

	bytes, err := base58.Decode(wif)
	if err != nil {
		return nil, err
	}

	hexa := hex.EncodeToString(bytes)

	hexa = hexa[2:len(hexa)]
	hexa = hexa[0 : len(hexa)-8]

	var privateKey PrivateKey
	privateKey.WIF = wif
	privateKey.Hex = hexa
	privateKey.Key, _ = new(big.Int).SetString(hexa, 16)
	privateKey.Network = network

	return &privateKey, nil
}

// PrivateFromHex imports a private key from its hex value
func PrivateFromHex(hexa string, network *Network) (*PrivateKey, error) {

	var p PrivateKey
	p.Key, _ = new(big.Int).SetString(hexa, 16)
	p.Hex = hexa
	/* Add network byte to the hex value */
	hexa = network.PrivKeyPrefix + hexa
	/* Convert to []byte */
	hexaB, err := hex.DecodeString(hexa)
	if err != nil {
		/* Retry */
		return nil, err
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
		return nil, err
	}

	wif := base58.Encode(hexaB)

	p.WIF = wif
	p.Network = network
	return &p, nil
}

// GeneratePrivateKey returns a PrivateKey
func GeneratePrivateKey(network *Network) *PrivateKey {

	/* Generate a number between 1 and 2^256 */
	key := generateRandomBigInt()

	hexa := bigIntToHex(key)
	if len(hexa) != 64 {
		return GeneratePrivateKey(network)
	}
	privateKey, err := PrivateFromHex(hexa, network)
	if err != nil {
		return GeneratePrivateKey(network)
	}
	privateKey.Key = key

	return privateKey
}

// AddPrivateKeys merge two private keys together by addition
func AddPrivateKeys(p1 *PrivateKey, p2 *PrivateKey, network *Network) (*PrivateKey, error) {

	pKey := new(big.Int)
	pKey = pKey.Add(p1.Key, p2.Key)
	pKey = pKey.Mod(pKey, secp256k1.N)

	hexa := bigIntToHex(pKey)

	privateKey, err := PrivateFromHex(hexa, network)
	return privateKey, err
}

// MultiplyPrivateKeys merge two private keys together by multiplication
func MultiplyPrivateKeys(p1 *PrivateKey, p2 *PrivateKey, network *Network) (*PrivateKey, error) {

	pKey := new(big.Int)
	pKey = pKey.Mul(p1.Key, p2.Key)
	pKey = pKey.Mod(pKey, secp256k1.N)

	hexa := bigIntToHex(pKey)

	privateKey, err := PrivateFromHex(hexa, network)
	return privateKey, err
}
