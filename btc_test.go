package btc

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckWIF(t *testing.T) {
	valid := CheckWIF("5KfonmXvbRoQycGJq3YfEEdu8K1zrtJXzejMjuh1rrPjbavb1Uc")
	assert.Equal(t, valid, true)

	valid = CheckWIF("5KfonmXvbRoQycGJq3YfEEdu8K1zrtJXzejMjuh1rrPjbavb1UC")
	assert.Equal(t, valid, false)
}

func TestGenerateKey(t *testing.T) {
	for i := 0; i < 5000; i++ {
		key := GeneratePrivateKey(MainNetwork)
		assert.Equal(t, true, len(key.WIF) == 51)
	}
}

func TestAddPrivateKeys(t *testing.T) {
	// key1 := GeneratePrivateKey(MainNetwork)
	// key2 := GeneratePrivateKey(MainNetwork)

	key1, _ := PrivateFromWIF("5KEurfmUXeJQM2Ao636USLyeB7H5mwz8EB4ABUzF5iFdNzTBne2", MainNetwork)
	key2, _ := PrivateFromWIF("5K8VA8kmG1VHKPjKtxcHW5tDk53BovDT8twmqnfQaa51dSuqd5d", MainNetwork)

	key, err := AddPrivateKeys(key1, key2, MainNetwork)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(key)

	key, err = MultiplyPrivateKeys(key1, key2, MainNetwork)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(key)
}

func TestGetPublicKey(t *testing.T) {
	for i := 0; i < 5000; i++ {
		key := GeneratePrivateKey(MainNetwork)
		pub, valid := key.GetPublicKey()
		if !valid {
			log.Fatal(pub)
		}

		hexa := pub.Hex(false)
		PublicFromHex(hexa, *MainNetwork)
		// log.Println(pub.Hex(true))
	}
}
