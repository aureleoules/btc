package btc

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewMnemonic(t *testing.T) {

	var wordLength = []int{
		12, 15, 18, 21, 24,
	}

	for _, l := range wordLength {
		for i := 0; i < 10000; i++ {
			phrase, err := NewMnemonic(l, EnglishWordlist)
			assert.Nil(t, err)
			assert.Equal(t, l, len(strings.Split(phrase, " ")))
		}
	}
}

func TestNewSeedFromMnemonic(t *testing.T) {

	NewSeedFromMnemonic("march assault engine warrior talent swarm pluck job prepare knife pipe man student dice receive analyst salute art clean wood enemy tourist lunch like", "", EnglishWordlist)

}
