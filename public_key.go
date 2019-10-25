package btc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math/big"

	"github.com/ThePiachu/Go/mymath/ripemd160"
	"github.com/mr-tron/base58"
)

// PublicFromHex imports a public key from its hex value
func PublicFromHex(hexa string, network *Network) (*PublicKey, error) {
	// log.Println(len(hexa), hexa)
	var publicKey PublicKey
	publicKey.Network = network

	prefix := hexa[0:2]

	if prefix == "04" {
		/* Uncompressed */
		x := hexa[2:66]
		y := hexa[66:130]
		publicKey.X, _ = new(big.Int).SetString(x, 16)
		publicKey.Y, _ = new(big.Int).SetString(y, 16)

	} else if prefix == "03" || prefix == "02" {
		x := hexa[2:66]
		publicKey.X, _ = new(big.Int).SetString(x, 16)

		y, onCurve := secp256k1.GetY(publicKey.X)
		if !onCurve {
			return nil, errors.New("point is not on secp256k1 curve")
		}

		parity := new(big.Int)
		if prefix == "02" {
			parity.SetInt64(0)
		} else {
			parity.SetInt64(1)
		}

		/* If parity is not wrong, use negative value mod secp256k1.N */
		yMod := new(big.Int).Set(y)
		if yMod.Mod(y, big.NewInt(2)).Cmp(parity) != 0 {
			y = secp256k1.MultMod(y, big.NewInt(-1))
		}

		publicKey.Y = y
	} else {
		return nil, errors.New("unsupported public key format")
	}
	return &publicKey, nil
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
	for len(pXHex) < 64 {
		pXHex = "0" + pXHex
	}
	for len(pYHex) < 64 {
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
