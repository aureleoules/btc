package btc

import (
	"math/big"
	"strings"
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

func TestPrivateFromHex(t *testing.T) {
	var hexArray = []struct {
		Hex     string // Input
		WIF     string // Corresponding WIF
		Network *Network
	}{
		// Main network
		{"42EE9BFFA29658554203A7D82456B4CBB9286ABE8D781D6C94C080260A9F24D6", "5JKmGh5KasctVb3o9p1eNZmgqgRNvAUTmVBs9aca5VJHHMFtMgc", MainNetwork},
		{"8613DFD6C099751DCC4020EF6F9BCD3C00F4565A15B26979B4B93C045D0A5CEB", "5JqLR1PX9UWPkiPus9ontEPXo4KitgoiYCkHaFoDh5hJdDJJmcK", MainNetwork},
		{"aef29c9770a9f6b9da86e37fc12a334eeffb02f967a55ba125deb77736ee3fc1", "5K9LPKv2VsbmAMhcEiNQnU2bTiNavtap1Ex6EMN1MFkTRZHi26E", MainNetwork},
		{"ca9a14d902fe536d9265862a8a5f21a8520dc215c0c10da0a9d5831aadcc520f", "5KMWmt74aaabx8bxumCoXzniNwfdPTTP4y2SG8D31Mzt79FemR9", MainNetwork},
		{"3610d7b143edd8bf2b5aaea942d59e7f3532d7ac340d5fd4e118c18e010ebd2d", "5JE6ctXTzE8JK5Qaw1FUtR9kNiYsyBicuwdR2jn982sfn9BL2Ku", MainNetwork},
		{"7504089115c9349ee5c04b129e1aea1c661f4c9c0f4c415dc9dd3aa791de7d10", "5JhpbHXjDJTuPxeXs53FBY4Hd4oZoS1RboswXNn3udEG6XtTdA8", MainNetwork},
		{"b03c2e8976c7963b472ac71cafc9458955e9743f7682c2409218cb31397c10d7", "5K9uGdHuajFab23DZFCv3EBN2bRwkifZiZRNbUoUgyn9g8UFMTu", MainNetwork},

		// Test network
		{"bc18f76841a483825323c48a26830734f0b496f89de498f7d4b47b15231eb482", "931krx7yFnVSoHb1JxeN1W2rrhWARbNfiK3BA3xVZZrfgALvkMy", TestNetwork},
		{"11d82d8c5dfd251556e8f49d020171cfd9d993d0c95c3bd8a3641ece5da1a293", "91imyYBEzyfb2d45tX81JucjFsCvidtKYwxbZXP6f431rY1mV8E", TestNetwork},
		{"3ce1461994adb57fde42d6595ab53aff95392abb4f1b9d08fda5af284feb40b2", "923jG4W4c83BacqWFTLHYCwaRw2YRR9umK9ZeQ2CtJfRLZLC8k6", TestNetwork},
		{"4f60b2ff5b9f83d9549d69b86d4a540c5b3d9e0df19fa8c2716e7fc6eb053b1d", "92Bsm5dR62dXoEeTVAD899EEAtKBQoBQ68BnX4GC98TWnnaTWT5", TestNetwork},
		{"94442137a9cfdd302f34773b2ed04fe038038d81c09af352a216af5507cf5035", "92iDRThnHRquXbFLgZVdYzFjVUYz8difQtwjeMRRULKNbxNWkKV", TestNetwork},
		{"3663d354de4bc3b83c0041d63f829ab56ac1d6bbc5f9b1914afdbf2032ae0edc", "91zsUsNprBX2FKgfotXp2TtG1KhrDekVK2ppEuzLRVjeyq8FEHa", TestNetwork},
		{"c96e8294cc865241c45aa3936b4aea503039bcad2c3c28e85cbcb55158f80174", "937dTvv4mUCZFbHqaom9uPUAFhNPTVdeWZ454xKUiywubknhRV7", TestNetwork},
		{"1af1af738881e068cc13dcd7cd45dee6542206612df83cde8bbe6246626945ed", "91nnQwn6kyNo56s2umtUBoUbuB9FyU8vuQzQjG4ZfFKV354kAwt", TestNetwork},
		{"5b1338b2e841fe88f256ee18575c7da626bf2f2faf218e7598d38d6bd2f61fc0", "92H2Z5s2Mwy3XTJTmeRdc4q75suMonU1jqow36yqe5UQcZvLxu7", TestNetwork},
	}

	for _, value := range hexArray {
		privateKey, err := PrivateFromHex(value.Hex, value.Network)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, value.WIF, privateKey.WIF)
	}

	_, err := PrivateFromHex("8613DFD6C099751DCC4020EF6F9BCD3C00F4565A15B26979B4B93C045D0A5CE", MainNetwork)
	assert.NotNil(t, err)
	_, err = PrivateFromHex("8613DFD6C099751DCC4020EF6F9BCD3C00F4565A15B26979B4B93C045D0A5CEB1", MainNetwork)
	assert.NotNil(t, err)
}

func TestPrivateFromWIF(t *testing.T) {
	var hexArray = []struct {
		Hex     string // Input
		WIF     string // Corresponding WIF
		Network *Network
	}{
		// Main network
		{"42EE9BFFA29658554203A7D82456B4CBB9286ABE8D781D6C94C080260A9F24D6", "5JKmGh5KasctVb3o9p1eNZmgqgRNvAUTmVBs9aca5VJHHMFtMgc", MainNetwork},
		{"8613DFD6C099751DCC4020EF6F9BCD3C00F4565A15B26979B4B93C045D0A5CEB", "5JqLR1PX9UWPkiPus9ontEPXo4KitgoiYCkHaFoDh5hJdDJJmcK", MainNetwork},
		{"aef29c9770a9f6b9da86e37fc12a334eeffb02f967a55ba125deb77736ee3fc1", "5K9LPKv2VsbmAMhcEiNQnU2bTiNavtap1Ex6EMN1MFkTRZHi26E", MainNetwork},
		{"ca9a14d902fe536d9265862a8a5f21a8520dc215c0c10da0a9d5831aadcc520f", "5KMWmt74aaabx8bxumCoXzniNwfdPTTP4y2SG8D31Mzt79FemR9", MainNetwork},
		{"3610d7b143edd8bf2b5aaea942d59e7f3532d7ac340d5fd4e118c18e010ebd2d", "5JE6ctXTzE8JK5Qaw1FUtR9kNiYsyBicuwdR2jn982sfn9BL2Ku", MainNetwork},
		{"7504089115c9349ee5c04b129e1aea1c661f4c9c0f4c415dc9dd3aa791de7d10", "5JhpbHXjDJTuPxeXs53FBY4Hd4oZoS1RboswXNn3udEG6XtTdA8", MainNetwork},
		{"b03c2e8976c7963b472ac71cafc9458955e9743f7682c2409218cb31397c10d7", "5K9uGdHuajFab23DZFCv3EBN2bRwkifZiZRNbUoUgyn9g8UFMTu", MainNetwork},

		// Test network
		{"bc18f76841a483825323c48a26830734f0b496f89de498f7d4b47b15231eb482", "931krx7yFnVSoHb1JxeN1W2rrhWARbNfiK3BA3xVZZrfgALvkMy", TestNetwork},
		{"11d82d8c5dfd251556e8f49d020171cfd9d993d0c95c3bd8a3641ece5da1a293", "91imyYBEzyfb2d45tX81JucjFsCvidtKYwxbZXP6f431rY1mV8E", TestNetwork},
		{"3ce1461994adb57fde42d6595ab53aff95392abb4f1b9d08fda5af284feb40b2", "923jG4W4c83BacqWFTLHYCwaRw2YRR9umK9ZeQ2CtJfRLZLC8k6", TestNetwork},
		{"4f60b2ff5b9f83d9549d69b86d4a540c5b3d9e0df19fa8c2716e7fc6eb053b1d", "92Bsm5dR62dXoEeTVAD899EEAtKBQoBQ68BnX4GC98TWnnaTWT5", TestNetwork},
		{"94442137a9cfdd302f34773b2ed04fe038038d81c09af352a216af5507cf5035", "92iDRThnHRquXbFLgZVdYzFjVUYz8difQtwjeMRRULKNbxNWkKV", TestNetwork},
		{"3663d354de4bc3b83c0041d63f829ab56ac1d6bbc5f9b1914afdbf2032ae0edc", "91zsUsNprBX2FKgfotXp2TtG1KhrDekVK2ppEuzLRVjeyq8FEHa", TestNetwork},
		{"c96e8294cc865241c45aa3936b4aea503039bcad2c3c28e85cbcb55158f80174", "937dTvv4mUCZFbHqaom9uPUAFhNPTVdeWZ454xKUiywubknhRV7", TestNetwork},
		{"1af1af738881e068cc13dcd7cd45dee6542206612df83cde8bbe6246626945ed", "91nnQwn6kyNo56s2umtUBoUbuB9FyU8vuQzQjG4ZfFKV354kAwt", TestNetwork},
		{"5b1338b2e841fe88f256ee18575c7da626bf2f2faf218e7598d38d6bd2f61fc0", "92H2Z5s2Mwy3XTJTmeRdc4q75suMonU1jqow36yqe5UQcZvLxu7", TestNetwork},
	}

	for _, value := range hexArray {
		privateKey, err := PrivateFromWIF(value.WIF, value.Network)
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, strings.ToLower(value.Hex), strings.ToLower(privateKey.Hex))
	}

	_, err := PrivateFromWIF("5JE6ctXTzE8JK5Qaw1FUtR9kNiYsyBicuwdR2jn982sfn9BL2K", MainNetwork)
	assert.NotNil(t, err)
	_, err = PrivateFromWIF("5K9uGdHuajFab23DZFCv3EBN2bRwkifZiZRNbUoUgyn9g8UFMT", MainNetwork)
	assert.NotNil(t, err)
}
