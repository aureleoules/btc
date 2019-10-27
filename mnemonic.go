package btc

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// NewMnemonic generates a new mnemonic phrase
func NewMnemonic(words int, wordlist Wordlist) (string, error) {

	if wordlist == nil {
		return "", errors.New("invalid wordlist")
	}

	var entropyLength int
	switch words {
	case 12:
		entropyLength = 128
		break
	case 15:
		entropyLength = 160
		break
	case 18:
		entropyLength = 192
		break
	case 21:
		entropyLength = 224
		break
	case 24:
		entropyLength = 256
		break
	default:
		return "", errors.New("unsupported mnemonic length")
	}

	/* Generate entropy */
	np256 := big.NewInt(2)
	np256.Exp(np256, big.NewInt(int64(entropyLength)), nil)
	entropy, err := rand.Int(rand.Reader, np256)
	if err != nil {
		return "", err
	}

	sha := sha256.New()
	sha.Write(entropy.Bytes())
	hash := sha.Sum(nil)

	checksumLength := entropyLength / 32

	hashInt := new(big.Int).SetBytes(hash)

	hashBinary := fmt.Sprintf("%b", hashInt)
	checksumBinary := hashBinary[0:checksumLength]

	b := fmt.Sprintf("%b", entropy)

	for len(b) < entropyLength {
		b = "0" + b
	}

	b = b + checksumBinary
	binary, _ := new(big.Int).SetString(b, 2)

	var phrase []string
	for i := 0; i < len(b); i += 11 {
		str := ""
		for j := i; j-i < 11; j++ {
			if binary.Bit(j) == 0 {
				str += "0"
			} else {
				str += "1"
			}
		}
		n, _ := new(big.Int).SetString(str, 2)
		phrase = append(phrase, wordlist[n.Int64()])
	}

	return strings.Join(phrase, " "), nil
}
