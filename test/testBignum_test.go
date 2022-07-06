package common

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDiv(t *testing.T) {
	p := new(big.Int).SetUint64(101)
	s := new(big.Int).SetUint64(99)

	a := NewXBigNum(p, s, new(big.Int).SetUint64(50), new(big.Int)) //50
	b := NewXBigNum(p, s, new(big.Int), new(big.Int).SetUint64(62)) //62u
	a.Div(a, b)
	assert.Equal(t, a.V.Text(10), "0")
	assert.Equal(t, a.Vi.Text(10), "11")
}
