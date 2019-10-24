package btc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math/big"

	"github.com/aureleoules/ecdsa"
	"github.com/mr-tron/base58"
	"golang.org/x/crypto/ripemd160"
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

// PublicFromHex imports a public key from its hex value
func PublicFromHex(hexa string, network Network) (*PublicKey, error) {
	// log.Println(len(hexa), hexa)
	if len(hexa) != 130 {
		log.Println(hexa)
	}
	if hexa[0:2] == "04" {
		/* Uncompressed */
		x := hexa[2:66]
		y := hexa[66:130]
		log.Println("Uncompressed", x, y)
	} else if hexa[0:2] == "03" {
		// x := hexa[2:66]
		/* Compressed odd */
	} else if hexa[0:2] == "02" {
		// y := hexa[2:66]
		/* Compressed even */

	}
	return nil, nil
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

	publicKey.Network = p.Network

	return &publicKey, true
}

// Hex returns the public key in hex
func (p *PublicKey) Hex(compressed bool) string {
	key := ""

	/* If hex length is not even, make it even by placing a 0 before */
	pXHex := bigIntToHex(p.X)
	pYHex := bigIntToHex(p.Y)

	/* Add 0's until hex is 64 or 32 bytes long whether key is compressed or not */
	for len(pXHex) != 64 {
		pXHex = "0" + pXHex
	}
	for len(pYHex) != 64 {
		pYHex = "0" + pYHex
	}

	if !compressed {
		key += "04"

		key += pXHex
		key += pYHex
	} else {
		if p.Y.Bit(0) == 0 { /* Even */
			key += "02"
		} else {
			key += "03"
		}

		key += pXHex
	}
	return key
}

// Address computes the base58 public address
func (p *PublicKey) Address(compressed bool) (string, error) {
	hexa := p.Hex(compressed)
	bytes, err := hex.DecodeString(hexa)
	log.Println(len(hexa))
	log.Println(hexa)
	if err != nil {
		log.Println("ERROR")
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
	extendedRipemd := p.Network.PubKeyHashPrefix + hexa

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

// AddPublicKeys merge two public keys together by addition
// func AddPublicKeys(p1 *PublicKey, p2 *PublicKey, compressed bool, network *Network) (*PublicKey, error) {

// 	p1Big, _ := new(big.Int).SetString(p1.Hex(compressed), 16)
// 	p2Big, _ := new(big.Int).SetString(p2.Hex(compressed), 16)

// 	pKey := new(big.Int)
// 	pKey = pKey.Add(p1Big, p2Big)
// 	pKey = pKey.Mod(pKey, secp256k1.N)

// 	hexa := bigIntToHex(pKey)

// 	publicKey := PublicKey{}

// 	return privateKey, err
// }
