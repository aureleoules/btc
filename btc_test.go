package btc

import (
	"math/big"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {

	// SetNetworkByte("80")

	// key := GeneratePrivateKey()
	// log.Println(key)
}

func TestGetPublicAddress(t *testing.T) {
	SetNetworkByte("80")

	// key := GeneratePrivateKey()

	private, _ := new(big.Int).SetString("38991C9EC1386F58ACCB001B5868EA0E9864ED4FB288094C8CC561893F17F234", 16)
	key := PrivateKey{
		Key: private,
		WIF: "5JFDJaLmZx2T1Ap3iBFELmyrYjXEofjrgdjeCRcHuLcF8ceGHMm",
	}

	key.GetPublicAddress()
}
