package common

import (
	"math"
	"math/big"
	"testing"

	"github.com/meshplus/crypto"
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

// Copy deep copy
func Copy(dst, src []crypto.FieldElement) {
	n := int(math.Min(float64(len(dst)), float64(len(src))))
	for i := 0; i < n; i++ {
		dst[i] = src[i].Copy()
	}
}
