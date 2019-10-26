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

func TestWIF(t *testing.T) {
	wifArray := []string{
		"5Jw5VXRjdyojUobJQ96Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD",
		"5KdoUDYDYSYQbC4oyjTszeeEBhjydEsJpdM9v1ziTFAkEeR2oBb",
		"5KctWoGYRZBYsXeiBJQJoJwtoSPMB4CF97K7LgMsHhHuUphUcQc",
		"5K8z81Wdq6L5ZRcFdQMpgnvaQQc8pesRLybsf5dCSKgFeeb2wRC",
		"5Kjc8GtRf22XKXFkxCZzCdjpuXrqw8u7sxkWUBkT7KeiRBBTVps",
		"5JLk1eZM6MMSfji4DhHgbHTcEzRQw5rNB85E1nF8TwsYfZhwDVe",
		"5JmvnCKj4PthjAJ3LAaPK7xoMah6mRMLB3tqQmZqioSYcDaDgVL",
		"5JCTBTAkMm1fqJaYNBtorJjPQtCK19Leh6DhsmbnraRNBuMG31B",
		"5J5HCukSWeQKnhmthv4nS4FMvbuvek1iqiLbXbemJCZDBd5jPF8",
		"5JveaFJBvAoJoMHTjFb6voQYi6xdECpjzUd7av6UFuAr3Zer7tv",
		"5HyA68w1SbNiX23Wex9qLMcvA68sYsXiDajSsBjW48gTS4cvCZ9",
		"5JP3yj2MozTDzHSkfYbcsooCTjpxCL298pPvkdx3WCMknKmqqm4",
		"5JgEeMNEHQG36txKhC7as54sTZRnr2burSBGBsmn3wE8jiWY4UX",
		"5Jttm9vDkXKYZBgrmPraGoHGtMcsrzgJqUJAk7a6vGvp2iqu1qG",
		"5JLot2SubTSJtEpyWUmnGqgbYVMDNdTBdBzPKaMfSoa1F21eeDt",
		"5K75MjFaxqJQYQvr5yH4nT3MVMjHQ3eBDChWYJ4D6WGMgXnoxCL",
		"5JBxKUAFL9526rQcTYAoJcFw4QLYPRHWXmRKVX88jafJLfyTqVE",
		"5JGed5wMstzeiqseHXHD5C8fnoqcaYSWwFbxS5HbTETRnof32qM",
		"5Kg2qaL7S59XsQtqzf34mfernQQw5DUQ2Y2b8p3dtbcF6Ehwb7M",
		"5JyvFPg5NqRT3r51S9GYnNi13PZ44LNg6uN8XTCLudeUiENvvkV",
		"5J4DJXZTvS6VfzP9bMvfkUzX9HurnZN7G5LjXEvM6TmBherbgN7",
		"5KG564bEsdu4WrDtcUNKRVuhA9JXeJvXCFnXDFEL1xvzMdDMAx1",
		"5KVYHbZTRZbBHt4yWw8sn9Yrhxxbc8om68eFrwKd1uduVxnUtgK",
		"5KQ4KAJLKxnsmaowc5ot2ECsnBLjAfNfiipSeKnfw2QWSdvvwoK",
		"5KYG6ERJ62xGYCoBuuyiiLMQ3DYKehbEwBd4qXVrLD97FZe3HT6",
		"5JTxsCNXXbDqPq1QZvExrzWKG8Ls1zdQju8ieENmoTLhiM54KLh",
		"5K2VyPeSMZaE9VbWoLcjh9J5svc4r9nq1QpsjhMpQvvY7WsbtvP",
		"5JzVoGtMKCZAGaZmwFPQrVwexYVDpPSbLKUavaXgHxnRRXa252e",
		"5KhNa3UoBEVJZmwyDMKp4Wc4afmEYyGsBUzfWbyohyvQLEfxg5m",
		"5KGiw1sox8jKZbCzjaTBXKYXBJsMzd5MdZbdbNctebitNJs8daW",
		"5K3zrYZRvAUCfsE7KzRNwhowSe9t5DMVxir5N1Gw9bJqsUfU7Pr",
		"5KDuhcNgSumqwhagVZfPAgqfS9BcJJKXkhsiFyovvgd83jXsGX4",
		"5KCQDfiRAqowdXjbS81CC47ADY8mobh4mnSUZXaMcpmLMBZwCYX",
		"5KUzEjAKf5uZ5vvsTPxF5sVDsAhFZe1vAEaSuHv1rGpxPpXLXYf",
		"5K9iSbKSRUCQqbban5tGwooH9LbgybDURgB9KBPca7hwJMnSbo8",
		"5JrVLx8gEKbqHKKiP3S2KwbtASwrWvj2N7ztyNbhLyiK11EpWQB",
		"5KCAByRFMj5Ji3NtYhuR7dB8Z1GfaEyij89KgYzVdqU4ZK5VpkC",
		"5JGPBGfCfgWFTzgpVZBjzGQ8nGod3gYumWooheFZN3e4sL87z4w",
		"5JDCwx2jmaUBbyb2rtnNm5bSwDQ2E4oSCupcivAFkWDsK8L5b3X",
		"5J2u7HgEHvPfgKWemYVcKSxopYqRUPfhQbpVe1Ac429kGnmFgnq",
		"5K1YCjna7PM1Q9rZCaWRhn3PZUXkxWDWEhfZdX2K9bMnkKJkZiU",
	}

	for _, wif := range wifArray {
		assert.Equal(t, true, CheckWIF(wif))
	}

	/* Incorrect wif */
	wifArray = []string{
		"5Jw5VXRjdyojUobJQ9Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD",
		"5KdoUDYDYSYQbC4oyjTzeeEBhjydEsJpdM9v1ziTFAkEeR2oBb",
		"5KctWoGYRZBYsXeiBJQJJwtoSPMB4CF97K7LgMsHhHuUphUcQc",
		"5K8z81Wdq6L5ZRcFdQpgnvaQQc8pesRLybsf5dCSKgFeeb2wRC",
		"5Kjc8GtRf22XKXFkxCZzCjpuXrqw8u7sxkWUBkT7KeiRBBTVps",
		"5JLk1eZM6MMSfji4DhHgbHTcEzRQw5rNB85E1nF8TwsYfhwDVe",
		"5JmvnCKj4PthjAJ3LAPK7xoMah6mRMLB3tqQmZqioSYcDaDgVL",
		"5JCTBTAkMm1fqJaYNBorjPQtCK19Leh6DhsmbnraRNBuMG31B",
		"5J5HCukSWeQKnhmthv4nFMvbuvek1iqiLbXbemJCZDBd5jPF8",
		"5JveaFJBvAoJoMHTjFb6vQYi6xdECpjzUd7av6UFuAr3Zer7tv",
		"5HyA68w1SbNiX23Wex9qLMvA68sYsXiDajSsBjW48gTS4cvCZ9",
		"5JP3yj2MozTDzHSkfYbcsooTjpxCL298pPvkdx3WCMknKmqqm4",
		"5JgEeMNEHQG36txKhC7as54sZRnr2burSBGBsmn3wE8jiWY4UX",
		"Jttm9vDkXKYZBgrmPraGoHGtMcsrzgJqUJAk7a6vGvp2iqu1qG",
	}

	for _, wif := range wifArray {
		assert.Equal(t, false, CheckWIF(wif))
	}
}

func TestAddPrivateKeys(t *testing.T) {

	var wifArray = []struct {
		WIF1   string
		WIF2   string
		WIFSUM string
	}{
		{"5Jw5VXRjdyojUobJQ96Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD", "5KdoUDYDYSYQbC4oyjTszeeEBhjydEsJpdM9v1ziTFAkEeR2oBb", "5JorCq4qFY6vgAh8S6VNq8SQMPDZbJ9gThonMd1VizhCF5RMhSG"},
		{"5JBxKUAFL9526rQcTYAoJcFw4QLYPRHWXmRKVX88jafJLfyTqVE", "5KG564bEsdu4WrDtcUNKRVuhA9JXeJvXCFnXDFEL1xvzMdDMAx1", "5KdjprJQ8KQ6MhFE2p6De4RVzwp9pbLx1D94UbJiWfjeXdu6qkw"},
		{"5J4DJXZTvS6VfzP9bMvfkUzX9HurnZN7G5LjXEvM6TmBherbgN7", "5KGiw1sox8jKZbCzjaTBXKYXBJsMzd5MdZbdbNctebitNJs8daW", "5KWeerzBo7FpyaCsHjvxBknv6zxJa3aPApsatSVVWBdRuNC5tMg"},
	}

	for _, key := range wifArray {
		p1, err := PrivateFromWIF(key.WIF1, MainNetwork)
		assert.Nil(t, err)
		p2, err := PrivateFromWIF(key.WIF2, MainNetwork)
		assert.Nil(t, err)

		privateKey, err := AddPrivateKeys(p1, p2)
		assert.Nil(t, err)
		assert.Equal(t, key.WIFSUM, privateKey.WIF)
	}

	/* different network */
	p1, _ := PrivateFromWIF("937dTvv4mUCZFbHqaom9uPUAFhNPTVdeWZ454xKUiywubknhRV7", TestNetwork)
	p2, _ := PrivateFromWIF("5J4DJXZTvS6VfzP9bMvfkUzX9HurnZN7G5LjXEvM6TmBherbgN7", MainNetwork)

	_, err := AddPrivateKeys(p1, p2)
	assert.NotNil(t, err)

	/* Cannot add two same keys */
	p1, _ = PrivateFromWIF("5Jw5VXRjdyojUobJQ96Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD", MainNetwork)
	p2, _ = PrivateFromWIF("5Jw5VXRjdyojUobJQ96Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD", MainNetwork)

	_, err = AddPrivateKeys(p1, p2)
	assert.NotNil(t, err)

	/* Test network */
	wifArray = []struct {
		WIF1   string
		WIF2   string
		WIFSUM string
	}{
		{"931krx7yFnVSoHb1JxeN1W2rrhWARbNfiK3BA3xVZZrfgALvkMy", "92iDRThnHRquXbFLgZVdYzFjVUYz8difQtwjeMRRULKNbxNWkKV", "92CJwm76271zxzN5RQBBeXPp6fci5F6xjXF4WK169vbLcAqsJnz"},
		{"92iDRThnHRquXbFLgZVdYzFjVUYz8difQtwjeMRRULKNbxNWkKV", "91nnQwn6kyNo56s2umtUBoUbuB9FyU8vuQzQjG4ZfFKV354kAwt", "92v5fzDFNiaaNdDovo3Hn9SFXPWcjoTKFZ1R4p5jYy3AhGrZysb"},
		{"92H2Z5s2Mwy3XTJTmeRdc4q75suMonU1jqow36yqe5UQcZvLxu7", "91imyYBEzyfb2d45tX81JucjFsCvidtKYwxbZXP6f431rY1mV8E", "92QtNCmdhEzWL1TyzdCpxL9kUUvfA7x4E2qoHpxgiWujXLJhgo1"},
	}

	for _, key := range wifArray {
		p1, err := PrivateFromWIF(key.WIF1, TestNetwork)
		assert.Nil(t, err)
		p2, err := PrivateFromWIF(key.WIF2, TestNetwork)
		assert.Nil(t, err)

		privateKey, err := AddPrivateKeys(p1, p2)
		assert.Nil(t, err)
		assert.Equal(t, key.WIFSUM, privateKey.WIF)
	}

}

func TestMultiplyPrivateKeys(t *testing.T) {

	var wifArray = []struct {
		WIF1   string
		WIF2   string
		WIFSUM string
	}{
		{"5Jw5VXRjdyojUobJQ96Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD", "5KdoUDYDYSYQbC4oyjTszeeEBhjydEsJpdM9v1ziTFAkEeR2oBb", "5J9ySojosxzdVS4JFiPeWUpcUqb6T5EwobxZKaxXkD1w4TGR6wm"},
		{"5JBxKUAFL9526rQcTYAoJcFw4QLYPRHWXmRKVX88jafJLfyTqVE", "5KG564bEsdu4WrDtcUNKRVuhA9JXeJvXCFnXDFEL1xvzMdDMAx1", "5JApih4xtEmPzQHqWSbWG1Ev3SWKX7cbNRhqnwPG4NsUiUGkHkN"},
		{"5J4DJXZTvS6VfzP9bMvfkUzX9HurnZN7G5LjXEvM6TmBherbgN7", "5KGiw1sox8jKZbCzjaTBXKYXBJsMzd5MdZbdbNctebitNJs8daW", "5Jk6N33DfNusZSQk6puyg2mutWFrdHMEmLKY1wfNH9Nvr3hBycZ"},
	}

	for _, key := range wifArray {
		p1, err := PrivateFromWIF(key.WIF1, MainNetwork)
		assert.Nil(t, err)
		p2, err := PrivateFromWIF(key.WIF2, MainNetwork)
		assert.Nil(t, err)

		privateKey, err := MultiplyPrivateKeys(p1, p2)
		assert.Nil(t, err)
		assert.Equal(t, key.WIFSUM, privateKey.WIF)
	}

	/* different network */
	p1, _ := PrivateFromWIF("937dTvv4mUCZFbHqaom9uPUAFhNPTVdeWZ454xKUiywubknhRV7", TestNetwork)
	p2, _ := PrivateFromWIF("5J4DJXZTvS6VfzP9bMvfkUzX9HurnZN7G5LjXEvM6TmBherbgN7", MainNetwork)

	_, err := MultiplyPrivateKeys(p1, p2)
	assert.NotNil(t, err)

	/* Cannot add two same keys */
	p1, _ = PrivateFromWIF("5Jw5VXRjdyojUobJQ96Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD", MainNetwork)
	p2, _ = PrivateFromWIF("5Jw5VXRjdyojUobJQ96Psr8zmXZKHsjYgpLXf536ozN6uLZpNDD", MainNetwork)

	_, err = AddPrivateKeys(p1, p2)
	assert.NotNil(t, err)

	/* Test network */
	wifArray = []struct {
		WIF1   string
		WIF2   string
		WIFSUM string
	}{
		{"931krx7yFnVSoHb1JxeN1W2rrhWARbNfiK3BA3xVZZrfgALvkMy", "92iDRThnHRquXbFLgZVdYzFjVUYz8difQtwjeMRRULKNbxNWkKV", "93EZpcjYBGSUyracS6r2S7zuies3L5JTaA3aWq8e7MuzEsgJN79"},
		{"92iDRThnHRquXbFLgZVdYzFjVUYz8difQtwjeMRRULKNbxNWkKV", "91nnQwn6kyNo56s2umtUBoUbuB9FyU8vuQzQjG4ZfFKV354kAwt", "93QbCK1yjymCNzriUM6G5bfqetCGz1Ffm8cyE71N1gQhXRUhqpK"},
		{"92H2Z5s2Mwy3XTJTmeRdc4q75suMonU1jqow36yqe5UQcZvLxu7", "91imyYBEzyfb2d45tX81JucjFsCvidtKYwxbZXP6f431rY1mV8E", "91oqEbrxXNoT658oKbMau5zjmR8YDKdajFMFrC6cLixxSgXxmZV"},
	}

	for _, key := range wifArray {
		p1, err := PrivateFromWIF(key.WIF1, TestNetwork)
		assert.Nil(t, err)
		p2, err := PrivateFromWIF(key.WIF2, TestNetwork)
		assert.Nil(t, err)

		privateKey, err := MultiplyPrivateKeys(p1, p2)
		assert.Nil(t, err)
		assert.Equal(t, key.WIFSUM, privateKey.WIF)
	}

}
