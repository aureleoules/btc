package btc

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	keysToTest := 10000
	max, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140", 16)

	check := func(key *PrivateKey, networkPrefix string, network *Network) {
		/* network should stay the same */
		assert.Equal(t, key.Network, network)

		/* Base58 private keys start with 5 on the main network */
		assert.Equal(t, networkPrefix, key.WIF[0:1])
		/* Length should always be 51 */
		assert.Equal(t, 51, len(key.WIF))

		/* Private key hex should be of length 64 */
		assert.Equal(t, 64, len(key.Hex))

		/* Private key should be less than `max` but greater than 1 */
		assert.Equal(t, -1, key.Key.Cmp(max))
		assert.Equal(t, 1, key.Key.Cmp(big.NewInt(1)))
	}
	for i := 0; i < keysToTest; i++ {
		key := GeneratePrivateKey(MainNetwork)
		check(key, "5", MainNetwork)
	}
	for i := 0; i < keysToTest; i++ {
		key := GeneratePrivateKey(TestNetwork)
		check(key, "9", TestNetwork)
	}

}
