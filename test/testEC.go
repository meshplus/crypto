package common

import (
	"fmt"
	"math/big"
	"strings"

	"github.com/meshplus/crypto"
)

//NewCurvePoint new curve point
func (c *Curve) NewCurvePoint(scalar *big.Int) *CurvePoint {
	ret := &CurvePoint{
		C: c,
		X: NewBigNum(&c.Module, new(big.Int)),
		Y: NewBigNum(&c.Module, new(big.Int)),
	}
	if scalar == nil {
		ret.IsInf = true
		ret.Coef = &BigNumForTest{
			P: c.Older,
			V: new(big.Int).SetInt64(0),
		}
		return ret
	}
	ret.Coef = &BigNumForTest{
		P: c.Older,
		V: new(big.Int).Set(scalar),
	}

	switch {
	case scalar.Sign() == 0:
		ret.IsInf = true
	case scalar.Bit(0) == 1 && scalar.BitLen() == 1:
		ret.X.Set(c.Gx)
		ret.Y.Set(c.Gy)
	default:
		ret.ScalarBaseMult(scalar)
	}
	return ret
}

//CurvePoint point
type CurvePoint struct {
	C     *Curve
	X, Y  *BigNumForTest
	IsInf bool
	Coef  crypto.FieldElement
}

//DLP ECDLP
func (c *CurvePoint) DLP() *BigNumForTest {
	return c.Coef.(*BigNumForTest)
}

//IsInfinity return bool
func (c *CurvePoint) IsInfinity() bool {
	return c.IsInf
}

//Add add
func (c *CurvePoint) Add(p1 crypto.Point, p2 crypto.Point) crypto.Point {
	a, b := p1.(*CurvePoint), p2.(*CurvePoint)
	tmp := a.Coef.Copy().Add(a.Coef, b.Coef)
	defer func() {
		c.Coef = tmp
	}()
	if a.IsInf {
		c.Set(b)
		return c
	}

	if b.IsInf {
		c.Set(a)
		return c
	}

	if a.X.Equal(b.X) && a.Y.Equal(b.Y) {
		c = c.Double(a).(*CurvePoint)
		return c
	}

	if a.X.Equal(b.X) {
		c.SetInfinity()
		return c
	}

	ret := c.C.NewCurvePoint(nil)
	m1, m := NewBigNum(&c.C.Module, new(big.Int)), NewBigNum(&c.C.Module, new(big.Int))
	ret.X.Sub(a.Y, b.Y)
	m1.Sub(a.X, b.X)
	ret.X.Div(ret.X, m1)
	m.Set(ret.X) //m

	ret.X.Square(ret.X)
	ret.X.Sub(ret.X, a.X)
	ret.X.Sub(ret.X, b.X) //m^2-x1-x2

	m1.Sub(a.X, ret.X)
	m.Mul(m, m1)
	ret.Y.Sub(m, a.Y) //m(x1-x3)-y1

	c.X.Set(ret.X)
	c.IsInf = false
	c.Y.Set(ret.Y)
	c.Coef = tmp
	return c
}

//Set set value
func (c *CurvePoint) Set(p crypto.Point) crypto.Point {
	a := p.(*CurvePoint)
	c.IsInf = a.IsInf
	c.X.Set(a.X)
	c.Y.Set(a.Y)
	c.Coef.Set(a.Coef)
	return c
}

//Double double
func (c *CurvePoint) Double(p crypto.Point) crypto.Point {
	a := p.(*CurvePoint)
	if a.IsInf {
		c.SetInfinity()
		return c
	}
	tmp := c.C.NewCurvePoint(nil)
	tmp.Set(a)
	m, t1 := NewBigNum(&tmp.C.Module, new(big.Int)), NewBigNum(&tmp.C.Module, new(big.Int).SetUint64(3))
	m.Square(tmp.X)
	m.Mul(m, t1)
	m.Add(m, tmp.C.A)
	tmp.Y.Double(tmp.Y)
	m.Div(m, tmp.Y) //26

	tmp.X.Square(m)
	tmp.X.Sub(tmp.X, a.X)
	tmp.X.Sub(tmp.X, a.X)

	t1.Sub(a.X, tmp.X)
	t1.Mul(t1, m)
	tmp.Y.Sub(t1, a.Y)
	c.X.Set(tmp.X)
	c.Y.Set(tmp.Y)
	c.IsInf = false
	c.Coef.Double(a.Coef)
	return c
}

//ScalarMult scalar multiplication
func (c *CurvePoint) ScalarMult(a crypto.Point, scalar *big.Int) crypto.Point {
	tmp, t := c.C.NewCurvePoint(nil), c.C.NewCurvePoint(nil)
	tmpBig := new(big.Int).SetBytes(a.(*CurvePoint).Coef.Regular(nil))
	tmpBig.Mul(tmpBig, scalar)
	defer func() {
		c.Coef = c.Coef.From(tmpBig)
	}()
	if scalar.Sign() == 0 || a.IsInfinity() {
		c.SetInfinity()
		return c
	}

	//将负数的scalar转换为正
	var e big.Int
	if scalar.Sign() < 0 {
		e.Add(scalar, &c.C.Module)
	} else {
		e.Set(scalar)
	}

	//如果e为1
	if e.BitLen() == 1 && e.Bit(0) == 1 {
		c.Set(a)
		return c
	}

	t.Set(a)
	tmp.Set(a)
	for i := scalar.BitLen() - 2; i >= 0; i-- {
		t.Double(t)
		if scalar.Bit(i) == 1 {
			t.Add(t, tmp)
		}
	}

	c.Set(t)
	return c
}

//ScalarBaseMult scalar multiplication with Base
func (c *CurvePoint) ScalarBaseMult(e *big.Int) crypto.Point {
	c.IsInf = false
	c.X.Set(c.C.Gx)
	c.Y.Set(c.C.Gy)
	c.ScalarMult(c, e)
	c.Coef.From(e)
	return c
}

//GetPosition get position
func (c *CurvePoint) GetPosition() crypto.Position {
	return crypto.G1
}

//GetPairing get pairing
func (c *CurvePoint) GetPairing() crypto.Pairing {
	return nil
}

//Marshal to bytes
func (c *CurvePoint) Marshal() []byte {
	if c.IsInf {
		return []byte("INFINITY")
	}
	var tmp big.Int
	buf := make([]byte, 0, 32)
	buf = c.X.Regular(buf)
	a := tmp.SetBytes(buf).Text(10)
	buf = c.Y.Regular(buf[:0])
	b := tmp.SetBytes(buf).Text(10)
	tmp.SetBytes(c.Coef.Regular(nil))
	return []byte(fmt.Sprintf("(%v,%v,%v)", a, b, tmp.Text(10)))
}

//Unmarshal parse
func (c *CurvePoint) Unmarshal(m []byte) ([]byte, error) {
	if string(m) == "INFINITY" {
		c.SetInfinity()
		c.Coef.SetZero()
		return m, nil
	}
	c.IsInf = false
	a := string(m[1:])
	r := strings.Split(a[:len(a)-1], ",")
	b1, _ := new(big.Int).SetString(r[0], 10)
	b2, _ := new(big.Int).SetString(r[1], 10)
	b3, _ := new(big.Int).SetString(r[2], 10)
	c.X.From(b1)
	c.Y.From(b2)
	c.Coef.From(b3)
	return nil, nil
}

//Neg neg
func (c *CurvePoint) Neg(point crypto.Point) crypto.Point {
	c.Set(point)
	c.Y.Neg(c.Y)
	c.Coef.Neg(c.Coef)
	return c
}

//SetInfinity set infinity
func (c *CurvePoint) SetInfinity() {
	c.X.SetZero()
	c.Y.SetZero()
	c.Coef.SetZero()
	c.IsInf = true
}
