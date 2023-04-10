package common

import (
	"testing"

	"github.com/meshplus/crypto"
)

func TestName(t *testing.T) {
	c := GetCurve257(true)
	g := c.GetBase(crypto.G1)

	t.Log(string(g.Add(g, g).Marshal()))
}
