package btc

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckWIF(t *testing.T) {
	valid := CheckWIF("5KfonmXvbRoQycGJq3YfEEdu8K1zrtJXzejMjuh1rrPjbavb1Uc")
	assert.Equal(t, valid, true)

	valid = CheckWIF("5KfonmXvbRoQycGJq3YfEEdu8K1zrtJXzejMjuh1rrPjbavb1UC")
	assert.Equal(t, valid, false)
}
