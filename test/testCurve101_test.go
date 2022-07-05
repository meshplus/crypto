package common

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"testing"

	"github.com/meshplus/crypto"
	"github.com/stretchr/testify/assert"
)

func TestGetRootOfUnity(t *testing.T) {
	c := GetCurve101(true)
	fmt.Println(c.GetRootOfUnity(8))
	fmt.Println(c.GetRootOfUnity(4))
	fmt.Println(c.GetRootOfUnity(2))
}

func RandomG1(pairing crypto.Pairing, r io.Reader) (*big.Int, crypto.Point) {
	i, _ := rand.Int(r, new(big.Int).SetInt64(17))
	for k, v := range curveTable {
		if v.Cmp(i) == 0 {
			ret := pairing.GetBase(crypto.G1)
			_, err := ret.Unmarshal([]byte(k))
			if err != nil {
				panic(err)
			}
			return new(big.Int).Set(&v), ret
		}
	}
	panic("never happen")
}

func RandomG2(pairing crypto.Pairing, r io.Reader) (*big.Int, crypto.Point) {
	i, _ := rand.Int(r, new(big.Int).SetInt64(17))
	for k, v := range twistTable {
		if v.Cmp(i) == 0 {
			ret := pairing.GetBase(crypto.G2)
			_, err := ret.Unmarshal([]byte(k))
			if err != nil {
				panic(err)
			}
			return new(big.Int).Set(&v), ret
		}
	}
	panic("never happen")
}

func TestBilinearity(t *testing.T) {
	tp := GetCurve101(true)
	for i := 0; i < 10; i++ {
		a, p1 := RandomG1(tp, rand.Reader)
		b, p2 := RandomG2(tp, rand.Reader)
		e1 := tp.Pair([]crypto.Point{p1, p1}, []crypto.Point{p2, p2})
		t.Log("a", a.String(), string(p1.Marshal()))
		t.Log("b", b.String(), string(p2.Marshal()))
		e2 := tp.Pair([]crypto.Point{tp.GetBase(crypto.G1), tp.GetBase(crypto.G1)}, []crypto.Point{tp.GetBase(crypto.G2), tp.GetBase(crypto.G2)})
		e2.ScalarMult(e2, a)
		e2.ScalarMult(e2, b)
		t.Log(string(e1.Marshal()))
		t.Log(string(e2.Marshal()))

		minusE2 := tp.NewPoint(crypto.GT).Neg(e2)
		e1.Add(e1, minusE2)

		assert.True(t, e1.IsInfinity())
	}
}

func TestSelfAddG1(t *testing.T) {
	tp := GetCurve101(true)
	_, Ga := RandomG1(tp, rand.Reader)
	Gb := tp.GetBase(crypto.G1)
	Gb.Double(Ga)
	mb := Gb.Marshal()

	Ga.Add(Ga, Ga)
	ma := Ga.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestG1Neg(t *testing.T) {
	tp := GetCurve101(true)
	_, Ga := RandomG1(tp, rand.Reader) //1
	t.Log(string(Ga.Marshal()))
	expect := Ga.Marshal()
	Gb := tp.GetBase(crypto.G1)
	Gb.Double(Ga)
	Gb.Double(Gb)

	Ga.Neg(Ga)
	Gb.Add(Gb, Ga)
	Gb.Add(Gb, Ga)
	Gb.Add(Gb, Ga)
	t.Log(string(Gb.Marshal()))
	assert.Equal(t, expect, Gb.Marshal())
}

func TestG2Neg(t *testing.T) {
	tp := GetCurve101(true)
	_, Ga := RandomG2(tp, rand.Reader) //1
	t.Log(string(Ga.Marshal()))
	expect := Ga.Marshal()
	Gb := tp.GetBase(crypto.G2)
	Gb.Double(Ga)
	Gb.Double(Gb)

	Ga.Neg(Ga)
	Gb.Add(Gb, Ga)
	Gb.Add(Gb, Ga)
	Gb.Add(Gb, Ga)
	t.Log(string(Gb.Marshal()))
	assert.Equal(t, expect, Gb.Marshal())
}

func TestG1Multi(t *testing.T) {
	tp := GetCurve101(true)
	_, Ga := RandomG1(tp, rand.Reader) //1
	Gb := tp.NewPoint(crypto.G1)

	Gb.Double(Ga)  //2
	Gb.Add(Gb, Ga) //3
	Gb.Double(Gb)  //6
	Gb.Double(Gb)  //12
	Gb.Add(Gb, Ga) //13
	Gb.Double(Gb)  //26
	Gb.Double(Gb)  //52
	Gb.Add(Gb, Ga) //53
	Gb.Double(Gb)  //106
	t.Log(string(Gb.Marshal()))

	Ga.ScalarMult(Ga, big.NewInt(106))
	t.Log(string(Ga.Marshal()))
	assert.Equal(t, Ga.Marshal(), Gb.Marshal())
}

func TestG2Multi(t *testing.T) {
	tp := GetCurve101(true)
	_, Ga := RandomG2(tp, rand.Reader) //1
	Gb := tp.GetBase(crypto.G2)

	Gb.Double(Ga)  //2
	Gb.Add(Gb, Ga) //3
	Gb.Double(Gb)  //6
	Gb.Double(Gb)  //12
	Gb.Add(Gb, Ga) //13
	Gb.Double(Gb)  //26
	Gb.Double(Gb)  //52
	Gb.Add(Gb, Ga) //53
	Gb.Double(Gb)  //106
	t.Log(string(Gb.Marshal()))

	Ga.ScalarMult(Ga, big.NewInt(106))
	t.Log(string(Ga.Marshal()))
	assert.Equal(t, Ga.Marshal(), Gb.Marshal())
}

func TestSelfAddG2(t *testing.T) {
	tp := GetCurve101(true)
	_, Ga := RandomG2(tp, rand.Reader)

	Gb := tp.GetBase(crypto.G2)
	Gb.Double(Ga)
	mb := Gb.Marshal()

	Ga.Add(Ga, Ga)
	ma := Ga.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestGT(t *testing.T) {
	tp := GetCurve101(true)
	gt := tp.GetBase(crypto.GT)
	for i := 2; i < 35; i++ {
		e := big.NewInt(int64(i))
		gt.ScalarBaseMult(e)
		t.Log(i-1, string(gt.Marshal()))
	}
	assert.Equal(t, "1+0i", string(gt.Marshal()))
}

func TestGTMarshal(t *testing.T) {
	tp := GetCurve101(true)
	k, _ := rand.Int(rand.Reader, &order)
	Ga := tp.NewPoint(crypto.GT).ScalarBaseMult(k)

	ma := Ga.Marshal()

	Gb := tp.NewPoint(crypto.GT)
	_, err := Gb.Unmarshal(ma)
	assert.Nil(t, err)
	mb := Gb.Marshal()

	if !bytes.Equal(ma, mb) {
		t.Fatal("bytes are different")
	}
}

func TestBatchScalarMultiplicationG1(t *testing.T) {
	tp := GetCurve101(true)
	Ga := tp.GetBase(crypto.G1) //1

	ret := make([]crypto.Point, 3)
	tp.BatchScalarMultiplicationG1([]*big.Int{big.NewInt(1), big.NewInt(7), big.NewInt(202)}, ret)

	assert.Equal(t, ret[0].Marshal(), Ga.Marshal())

	G2 := tp.NewPoint(crypto.G1).Double(Ga)
	G4 := tp.NewPoint(crypto.G1).Double(G2)
	G8 := tp.NewPoint(crypto.G1).Double(G4)
	G16 := tp.NewPoint(crypto.G1).Double(G8)
	G32 := tp.NewPoint(crypto.G1).Double(G16)
	G64 := tp.NewPoint(crypto.G1).Double(G32)
	G128 := tp.NewPoint(crypto.G1).Double(G64)

	//7 = 4+2+1
	Gb := tp.NewPoint(crypto.G1)
	Gb.Add(G4, G2)
	Gb.Add(Gb, Ga)
	assert.Equal(t, ret[1].Marshal(), Gb.Marshal())

	//202= 128+64+8+2
	Gc := tp.NewPoint(crypto.G1)
	Gc.Add(G128, G64)
	Gc.Add(Gc, G8)
	Gc.Add(Gc, G2)
	assert.Equal(t, ret[2].Marshal(), Gc.Marshal())
}

func TestBatchScalarMultiplicationG2(t *testing.T) {
	tp := GetCurve101(true)
	Ga := tp.GetBase(crypto.G2) //1

	ret := make([]crypto.Point, 3)
	tp.BatchScalarMultiplicationG2([]*big.Int{big.NewInt(1), big.NewInt(7), big.NewInt(202)}, ret)

	assert.Equal(t, ret[0].Marshal(), Ga.Marshal())

	//nolint
	G2_ := tp.NewPoint(crypto.G2).Double(Ga)
	G4 := tp.NewPoint(crypto.G2).Double(G2_)
	G8 := tp.NewPoint(crypto.G2).Double(G4)
	G16 := tp.NewPoint(crypto.G2).Double(G8)
	G32 := tp.NewPoint(crypto.G2).Double(G16)
	G64 := tp.NewPoint(crypto.G2).Double(G32)
	G128 := tp.NewPoint(crypto.G2).Double(G64)

	//7 = 4+2+1
	Gb := tp.NewPoint(crypto.G2)
	Gb.Add(G4, G2_)
	Gb.Add(Gb, Ga)
	assert.Equal(t, ret[1].Marshal(), Gb.Marshal())

	//202= 128+64+8+2
	Gc := tp.NewPoint(crypto.G2)
	Gc.Add(G128, G64)
	Gc.Add(Gc, G8)
	Gc.Add(Gc, G2_)
	assert.Equal(t, ret[2].Marshal(), Gc.Marshal())
}
