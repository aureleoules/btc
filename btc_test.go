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
		if len(key.WIF) != 51 {
			log.Println(key.WIF)
			log.Println("HEX", key.Hex)
		}
	}
}
