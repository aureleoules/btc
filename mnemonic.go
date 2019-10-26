package btc

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

// NewMnemonic generates a new mnemonic phrase
func NewMnemonic(length int, wordlist Wordlist) (string, error) {
	if length < 1 {
		return "", errors.New("invalid length")
	}
	if wordlist == nil {
		return "", errors.New("invalid wordlist")
	}

	var phrase []string
	for i := 0; i < length; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(wordlist))))
		if err != nil {
			return "", err
		}
		phrase = append(phrase, wordlist[n.Int64()])
	}

	return strings.Join(phrase, " "), nil
}
