package btc

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// func TestNewMnemonic(t *testing.T) {

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, FrenchWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, EnglishWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, JapaneseWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, KoreanWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, SpanishWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, ItalianWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, ChineseSimplifiedWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, ChineseTraditionalWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	for i := 0; i < 5; i++ {
// 		phrase, err := NewMnemonic(24, CzechWordlist)
// 		assert.Nil(t, err)
// 		phraseArray := strings.Split(phrase, " ")
// 		assert.Equal(t, 24, len(phraseArray))
// 	}

// 	_, err := NewMnemonic(24, nil)
// 	assert.NotNil(t, err)

// 	_, err = NewMnemonic(-5, FrenchWordlist)
// 	assert.NotNil(t, err)
// }

func TestNewMnemonic(t *testing.T) {

	var wordLength = []int{
		12, 15, 18, 21, 24,
	}

	for _, l := range wordLength {
		for i := 0; i < 100000; i++ {
			phrase, err := NewMnemonic(l, EnglishWordlist)
			assert.Nil(t, err)
			assert.Equal(t, l, len(strings.Split(phrase, " ")))
		}
	}

}
