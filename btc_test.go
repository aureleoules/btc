package btc

import (
	"log"
	"testing"
)

func TestMain(t *testing.T) {

	for i := 0; i < 5000; i++ {

		key := GeneratePrivateKey(MainNetwork)
		log.Println(key)
		pubKey, ok := key.GetPublicKey()
		log.Println(pubKey, ok)
		address, err := pubKey.Address(false)
		log.Println(address, err)
		if err != nil {
			panic(err)
		}
	}

}
