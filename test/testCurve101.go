package common

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"sync"

	"github.com/meshplus/crypto"
)

var curveTable map[string]big.Int
var twistTable map[string]big.Int
var initCurveOnce sync.Once
var one = big.NewInt(1)

//Curve101 a instance of a Curve101
var module big.Int
var order big.Int
var iSquare big.Int

func init() {
	module.SetInt64(101)
	order.SetInt64(17)
	iSquare.SetInt64(99)
	crypto.RegisterPairing(GetCurve101(false))
	crypto.RegisterPairing(GetCurve101(true))
}

//GetCurve101 get a curve for test
func GetCurve101(fft bool) crypto.Pairing {
	Curve101 := &Curve{
		SupportFFT: fft,
		A:          NewBigNum(&module, big.NewInt(0)),
		B:          NewBigNum(&module, big.NewInt(3)),
		Gx:         NewBigNum(&module, big.NewInt(1)),
		Gy:         NewBigNum(&module, big.NewInt(2)),
		G2x:        NewXBigNum(&module, &iSquare, big.NewInt(36), big.NewInt(0)),
		G2y:        NewXBigNum(&module, &iSquare, big.NewInt(0), big.NewInt(31)),
	}

	Curve101.Module.Set(&module)
	Curve101.Older.Set(&order)
	Curve101.Square.Set(&iSquare)

	initCurveOnce.Do(func() {
		G1g := Curve101.NewCurvePoint(one)
		G2g := Curve101.NewTwistPoint(one)

		G1 := Curve101.NewCurvePoint(nil)
		G2 := Curve101.NewTwistPoint(nil)
		curveTable = make(map[string]big.Int, 17)
		twistTable = make(map[string]big.Int, 17)
		for i := 0; i < 17; i++ {
			curveTable[string(G1.Marshal())] = *big.NewInt(int64(i))
			twistTable[string(G2.Marshal())] = *big.NewInt(int64(i))

			G1.Add(G1, G1g)
			G2.Add(G2, G2g)
		}
	})
	return Curve101
}

//Curve Y^2=X^3+ax+b mod Module
type Curve struct {
	SupportFFT bool
	Module     big.Int
	A, B       *BigNumForTest
	Gx, Gy     *BigNumForTest
	Older      big.Int

	Square   big.Int
	G2x, G2y *XBigNumForTest
}

//Marshal to bytes
func (c *Curve) Marshal() []byte {
	if c.SupportFFT {
		return []byte(crypto.CurveNameCurve101)
	}
	return []byte(crypto.CurveNameCurve101NonFFT)
}

//Unmarshal parse
func (c *Curve) Unmarshal(data []byte) ([]byte, error) {
	if bytes.Contains(data, []byte(crypto.CurveNameCurve101NonFFT)) {
		c.SupportFFT = false
		return data[len(crypto.CurveNameCurve101NonFFT):], nil
	} else if bytes.Contains(data, []byte(crypto.CurveNameCurve101)) {
		c.SupportFFT = true
		return data[len(crypto.CurveNameCurve101):], nil
	}

	return data, errors.New("curve: illegal data")
}

//GetModule get module
func (c *Curve) GetModule() *big.Int {
	return new(big.Int).Set(&c.Older)
}

//NewScalar new scalar
func (c *Curve) NewScalar() crypto.FieldElement {
	return NewBigNum(&c.Older, new(big.Int))
}

//PutScalar put scalar to pool
func (c *Curve) PutScalar(_ crypto.FieldElement) {
}

//GetRootOfUnity 找到v阶子群的元根,v是大于u的最小的2的幂
func (c *Curve) GetRootOfUnity(u uint64) (crypto.FieldElement, uint64, error) {
	if !c.SupportFFT {
		return nil, 0, crypto.ErrFFT
	}
	logOlder := bits.TrailingZeros64(u)

	var (
		g               crypto.FieldElement
		maxAll, maxSize int
	)

	//1 5 8 6 13 14 2 10 16 12 9 11 4 3 15 7
	switch c.Older.Int64() {
	case 17:
		g = c.NewScalar().SetInt64(5)
		maxAll = 16
		maxSize = 4
	case 97:
		g = c.NewScalar().SetInt64(5)
		maxAll = 96
		maxSize = 5
	case 257:
		g = c.NewScalar().SetInt64(3)
		maxAll = 256
		maxSize = 8
	}

	if logOlder > maxSize {
		return nil, 4 << 1, fmt.Errorf("order is too big, max is %v", maxSize<<1)
	}
	tmp := maxAll / (1 << logOlder)
	tmpBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(tmpBytes, uint64(tmp))
	//ret = g^{ 2^(4 - logOlder) }
	//g^{ 2^(4 - logOlder) }, g^{ 2^(4 - logOlder + log2)}, g^{ 2^(4 - logOlder + log3)} ... g^{ 2^(4)} = 1
	res2 := c.NewScalar().Exp(g, tmpBytes)
	return res2, 4 << 1, nil
}

//Name get name
func (c *Curve) Name() string {
	if c.SupportFFT {
		return crypto.CurveNameCurve101
	}
	return crypto.CurveNameCurve101NonFFT
}

//Pair compute pairing
func (c *Curve) Pair(point []crypto.Point, point2 []crypto.Point) crypto.Point {
	var ret = &gt{
		p: c,
		v: XBigNumForTest{
			V:  big.NewInt(1),
			Vi: big.NewInt(0),
		},
	}
	ret.v.P.Set(&module)
	ret.v.IS.Set(&iSquare)
	ret.SetInfinity()
	for i := range point {
		tmp := c.pairing(point[i], point2[i])
		ret.Add(ret, tmp)
	}
	return ret
}

//PairCheck compute pairing
func (c *Curve) PairCheck(point []crypto.Point, point2 []crypto.Point) bool {
	return c.Pair(point, point2).IsInfinity()
}

//IsOnCurve is on curve
func (c *Curve) IsOnCurve(point crypto.Point) error {
	var xx, yy *XBigNumForTest
	switch in := point.(type) {
	case *CurvePoint:
		xx, yy = convertToX(in.X, &c.Square), convertToX(in.Y, &c.Square)
	case *TwistPoint:
		xx, yy = convertToX(in.X, &c.Square), convertToX(in.Y, &c.Square)
	default:
		return fmt.Errorf("unknown point type")
	}
	tmp := NewXBigNum(&xx.P, &xx.IS, new(big.Int), new(big.Int))
	tmp.Square(xx)
	xx.Mul(xx, tmp)
	xx.Add(xx, convertToX(c.B, &c.Square))

	yy.Square(yy)
	if yy.Equal(xx) {
		return nil
	}
	return fmt.Errorf("is not on curve101")
}

//GetBase get base
func (c *Curve) GetBase(position crypto.Position) crypto.Point {
	switch position {
	case crypto.G1:
		return c.NewCurvePoint(one)
	case crypto.G2:
		return c.NewTwistPoint(one)
	default:
		ret := &gt{
			p: c,
			v: XBigNumForTest{
				V:  big.NewInt(7),
				Vi: big.NewInt(28),
			},
		}
		ret.v.P.Set(&module)
		ret.v.IS.Set(&iSquare)
		return ret
	}
}

//NewPoint new point
func (c *Curve) NewPoint(position crypto.Position) crypto.Point {
	switch position {
	case crypto.G1:
		return c.NewCurvePoint(nil)
	case crypto.G2:
		return c.NewTwistPoint(nil)
	default:
		ret := &gt{
			p: c,
			v: XBigNumForTest{
				V:  big.NewInt(1),
				Vi: big.NewInt(0),
			},
		}
		ret.v.P.Set(&module)
		ret.v.IS.Set(&iSquare)
		return ret
	}
}

//BatchScalarMultiplicationG1 batch multiplication
func (c *Curve) BatchScalarMultiplicationG1(scalars []*big.Int, ret []crypto.Point) {
	for i := range scalars {
		ret[i] = c.NewPoint(crypto.G1)
		ret[i].ScalarBaseMult(scalars[i])
	}
}

//BatchScalarMultiplicationG2 batch multiplication
func (c *Curve) BatchScalarMultiplicationG2(scalars []*big.Int, ret []crypto.Point) {
	for i := range scalars {
		ret[i] = c.NewPoint(crypto.G2)
		ret[i].ScalarBaseMult(scalars[i])
	}
}

//GetCurve97 get a curve for test
func GetCurve97(fft bool) crypto.Pairing {
	Curve97 := &Curve{
		SupportFFT: fft,
		Module:     module,
		A:          NewBigNum(&module, big.NewInt(0)),
		B:          NewBigNum(&module, big.NewInt(3)),
		Gx:         NewBigNum(&module, big.NewInt(1)),
		Gy:         NewBigNum(&module, big.NewInt(2)),
		Older:      *big.NewInt(97),

		Square: iSquare,
		G2x:    NewXBigNum(&module, &iSquare, big.NewInt(36), big.NewInt(0)),
		G2y:    NewXBigNum(&module, &iSquare, big.NewInt(0), big.NewInt(31)),
	}

	curveTable = make(map[string]big.Int, 97)
	twistTable = make(map[string]big.Int, 97)
	G1 := Curve97.NewCurvePoint(nil)
	G2 := Curve97.NewTwistPoint(nil)
	G1g := Curve97.NewCurvePoint(big.NewInt(1))
	G2g := Curve97.NewTwistPoint(big.NewInt(1))
	for i := 0; i < 97; i++ {
		curveTable[string(G1.Marshal())] = *big.NewInt(int64(i))
		twistTable[string(G2.Marshal())] = *big.NewInt(int64(i))

		G1.Add(G1, G1g)
		G2.Add(G2, G2g)
	}
	return Curve97
}

//GetCurve257 get a curve for test
func GetCurve257(fft bool) crypto.Pairing {
	Curve257 := &Curve{
		SupportFFT: fft,
		Module:     *big.NewInt(3083),
		A:          NewBigNum(&module, big.NewInt(0)),
		B:          NewBigNum(&module, big.NewInt(2)),
		Gx:         NewBigNum(&module, big.NewInt(3082)),
		Gy:         NewBigNum(&module, big.NewInt(1)),
		Older:      *big.NewInt(257), //协因子12

		Square: iSquare,
		G2x:    NewXBigNum(&module, &iSquare, big.NewInt(36), big.NewInt(0)),
		G2y:    NewXBigNum(&module, &iSquare, big.NewInt(0), big.NewInt(31)),
	}

	curveTable = make(map[string]big.Int, 257)
	twistTable = make(map[string]big.Int, 257)
	G1 := Curve257.NewCurvePoint(nil)
	G2 := Curve257.NewTwistPoint(nil)
	G1g := Curve257.NewCurvePoint(big.NewInt(1))
	G2g := Curve257.NewTwistPoint(big.NewInt(1))
	for i := 0; i < 257; i++ {
		curveTable[string(G1.Marshal())] = *big.NewInt(int64(i))
		twistTable[string(G2.Marshal())] = *big.NewInt(int64(i))

		G1.Add(G1, G1g)
		G2.Add(G2, G2g)
	}
	return Curve257
}
