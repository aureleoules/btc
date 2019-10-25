package btc

import (
	"log"
	"testing"
)

func TestAddPublicKeys(t *testing.T) {
	pKey1, err := PublicFromHex("04D0431B1FB23BF0D4D9B95B26419CBA50409D0FA610E9274B2F418BDCA20D42E5779225B9A70BFC715149B73AE91BC31A22D1B123F4872C5F31864725A5A59832", MainNetwork)
	if err != nil {
		log.Fatal(err)
	}
	pKey2, err := PublicFromHex("040017FDA2210BFCBCC11D7E8845883D8A5C60A72DE7EA840A4D20A9E92681F673BE823236512B1E28DA42AA7446C39EB70B562C24CC299F0978ECD7C8F37C22A6", MainNetwork)
	if err != nil {
		log.Fatal(err)
	}

	key, err := AddPublicKeys(pKey1, pKey2, false)
	log.Println(key.Format(false))
}
