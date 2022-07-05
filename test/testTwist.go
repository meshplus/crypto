package common

import (
	"bytes"
	"fmt"
	"math/big"
	"reflect"
	"strings"

	"github.com/meshplus/crypto"
)

//TwistPoint extern point
type TwistPoint struct {
	C     *Curve
	X, Y  *XBigNumForTest
	IsInf bool
}

//IsInfinity is infinity
func (t *TwistPoint) IsInfinity() bool {
	return t.IsInf
}

//NewTwistPoint new point
func (c *Curve) NewTwistPoint(scalar *big.Int) *TwistPoint {
	ret := &TwistPoint{
		C: c,
		X: NewXBigNum(&c.Module, &c.Square, new(big.Int), new(big.Int)),
		Y: NewXBigNum(&c.Module, &c.Square, new(big.Int), new(big.Int)),
	}
	if scalar == nil {
		ret.IsInf = true
		return ret
	}

	switch {
	case scalar.Sign() == 0:
		ret.IsInf = true
	case scalar.BitLen() == 1 && scalar.Bit(0) == 1:
		ret.X.Set(c.G2x)
		ret.Y.Set(c.G2y)
	default:
		ret.ScalarBaseMult(scalar)
	}
	return ret
}

//Add add
func (t *TwistPoint) Add(p1 crypto.Point, p2 crypto.Point) crypto.Point {
	a, b := p1.(*TwistPoint), p2.(*TwistPoint)
	if a.X.Equal(b.X) && a.Y.Equal(b.Y) && a.IsInf == b.IsInf {
		return t.Double(a)
	}
	if a.IsInf {
		t.Set(b)
		return t
	}

	if b.IsInf {
		t.Set(a)
		return t
	}

	if a.X.Equal(b.X) {
		t.SetInfinity()
		return t
	}

	ret := t.C.NewTwistPoint(nil)
	m1, m := NewXBigNum(&t.C.Module, &t.C.Square, new(big.Int), new(big.Int)),
		NewXBigNum(&t.C.Module, &t.C.Square, new(big.Int), new(big.Int))
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

	t.X.Set(ret.X)
	t.IsInf = false
	t.Y.Set(ret.Y)
	return t
}

//Set set value
func (t *TwistPoint) Set(p crypto.Point) crypto.Point {
	a := p.(*TwistPoint)
	t.IsInf = a.IsInf
	t.X.Set(a.X)
	t.Y.Set(a.Y)
	return t
}

//Double  double
func (t *TwistPoint) Double(p crypto.Point) crypto.Point {
	a := p.(*TwistPoint)
	if a.IsInf {
		t.SetInfinity()
		return t
	}
	tmp := t.C.NewTwistPoint(nil)
	tmp.Set(a)
	m, t1 := NewXBigNum(&tmp.C.Module, &tmp.C.Square, new(big.Int), new(big.Int)),
		NewXBigNum(&tmp.C.Module, &tmp.C.Square, new(big.Int).SetInt64(3), new(big.Int))
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
	t.X.Set(tmp.X)
	t.Y.Set(tmp.Y)
	t.IsInf = false
	return t
}

//ScalarMult scalar multiplication
func (t *TwistPoint) ScalarMult(a crypto.Point, scalar *big.Int) crypto.Point {
	if scalar.Sign() == 0 {
		t.IsInf = true
		return t
	}
	if scalar.Sign() < 0 {
		scalar.Add(scalar, &t.C.Module)
	}
	tmp1, tmp2 := t.C.NewTwistPoint(nil), t.C.NewTwistPoint(nil)
	tmp1.Set(a)
	tmp2.Set(a)
	for i := scalar.BitLen() - 2; i >= 0; i-- {
		tmp1.Double(tmp1)
		if scalar.Bit(i) != 0 {
			tmp1.Add(tmp1, tmp2)
		}
	}
	t.Set(tmp1)
	return t
}

//ScalarBaseMult scalar multiplication with Base
func (t *TwistPoint) ScalarBaseMult(e *big.Int) crypto.Point {
	t.IsInf = false
	t.X.Set(t.C.G2x)
	t.Y.Set(t.C.G2y)
	return t.ScalarMult(t, e)
}

//GetPosition get position
func (t *TwistPoint) GetPosition() crypto.Position {
	return crypto.G2
}

//GetPairing get pairing
func (t *TwistPoint) GetPairing() crypto.Pairing {
	return t.C
}

//Marshal marshal
func (t *TwistPoint) Marshal() []byte {
	if t.IsInf {
		return []byte("INFINITY")
	}
	a := t.X.V.Text(10)
	b := t.X.Vi.Text(10)
	c := t.Y.V.Text(10)
	d := t.Y.Vi.Text(10)
	x, y := "", ""
	if b == "0" {
		x = a
	} else {
		x = fmt.Sprintf("%v+%vu", a, b)
	}

	if d == "0" {
		y = c
	} else {
		y = fmt.Sprintf("%v+%vu", c, d)
	}
	return []byte(fmt.Sprintf(`(%v,%v)`, x, y))
}

//Unmarshal unmarshal
func (t *TwistPoint) Unmarshal(m []byte) ([]byte, error) {
	in := string(m)
	if in == "INFINITY" {
		t.SetInfinity()
		return m, nil
	}
	t.IsInf = false
	in = in[1:]
	in = in[:len(in)-1]
	r := strings.Split(in, ",")
	x, y := r[0], r[1]
	if strings.HasSuffix(x, "u") {
		x = x[:len(x)-1]
		r = strings.Split(x, "+")
		t.X.V.SetString(r[0], 10)
		t.X.Vi.SetString(r[1], 10)
	} else {
		t.X.V.SetString(x, 10)
		t.X.Vi.SetInt64(0)
	}
	if strings.HasSuffix(y, "u") {
		y = y[:len(y)-1]
		r = strings.Split(y, "+")
		t.Y.V.SetString(r[0], 10)
		t.Y.Vi.SetString(r[1], 10)
	} else {
		t.Y.V.SetString(y, 10)
		t.Y.Vi.SetInt64(0)
	}
	return nil, nil
}

//Neg neg
func (t *TwistPoint) Neg(point crypto.Point) crypto.Point {
	t.Set(point)
	t.Y.Neg(t.Y)
	return t
}

//SetInfinity set infinity
func (t *TwistPoint) SetInfinity() {
	t.IsInf = true
}

func (c *Curve) pairing(G1, G2 crypto.Point) *gt {
	P, Q := G1.(*CurvePoint), G2.(*TwistPoint)
	pStr := string(P.Marshal())
	qStr := string(Q.Marshal())

	s1, ok := curveTable[pStr]
	if !ok {
		panic(fmt.Sprintf("wrong status: %v", pStr))
	}

	s2, ok := twistTable[qStr]
	if !ok {
		panic(fmt.Sprintf("wrong status: %v", qStr))
	}

	a, b := &s1, &s2
	a.Mul(a, b)
	a.Mod(a, &order)

	ret := &gt{
		p: c,
		v: XBigNumForTest{
			V:  new(big.Int).SetInt64(gtTable[a.Int64()][0]),
			Vi: new(big.Int).SetInt64(gtTable[a.Int64()][1]),
		},
	}
	ret.v.P.Set(&module)
	ret.v.IS.Set(&iSquare)
	return ret
}

//PrintArray print field element array
func PrintArray(in interface{}) string {
	vin := reflect.ValueOf(in)
	if vin.Kind() != reflect.Slice {
		return "it's not a slice"
	}
	var ret strings.Builder
	length := vin.Len()
	for i := 0; i < length; i++ {
		vv := vin.Index(i)
		if vv.IsNil() {
			ret.WriteString("unknown")
		} else {
			ret.WriteString(fmt.Sprintf("%v:", i))
			switch r := vv.Interface().(type) {
			case *big.Rat:
				ret.WriteString(r.RatString())
			case fmt.Stringer:
				ret.WriteString(r.String())
			case []byte:
				ret.WriteString(new(big.Int).SetBytes(r).String())
			default:
				ret.WriteString(vv.String())
			}
		}

		if i != length-1 {
			ret.WriteString(", ")
		}
	}
	return ret.String()
}

type gt struct {
	p crypto.Pairing
	v XBigNumForTest
}

func (g *gt) Marshal() []byte {
	return []byte(g.v.String())
}

func (g *gt) Unmarshal(in []byte) ([]byte, error) {
	vEnd := bytes.IndexByte(in, '+')
	viEnd := bytes.IndexByte(in, 'i')
	g.v.V.SetString(string(in[:vEnd]), 10)
	g.v.Vi.SetString(string(in[vEnd+1:viEnd]), 10)
	return nil, nil
}

func (g *gt) Add(point crypto.Point, point2 crypto.Point) crypto.Point {
	a, b := point.(*gt), point2.(*gt)
	g.v.Mul(&a.v, &b.v)
	return g
}

func (g *gt) Set(point crypto.Point) crypto.Point {
	b := point.(*gt)
	g.v.Set(&b.v)
	return g
}

func (g *gt) Double(point crypto.Point) crypto.Point {
	b := point.(*gt)
	g.v.Square(&b.v)
	return g
}

func (g *gt) Neg(point crypto.Point) crypto.Point {
	b := point.(*gt)
	g.v.Inv(&b.v)
	return g
}

func (g *gt) ScalarMult(point crypto.Point, element *big.Int) crypto.Point {
	if element.Sign() < 0 {
		element.Add(element, g.p.GetModule())
	}
	p := point.(*gt)
	p.v.Exp(&p.v, element.Bytes())
	g.Set(p)
	return g
}

func (g *gt) ScalarBaseMult(element *big.Int) crypto.Point {
	p := g.p.GetBase(crypto.GT).(*gt)
	p.v.Exp(&p.v, element.Bytes())
	g.Set(p)
	return g
}

func (g *gt) GetPosition() crypto.Position {
	return crypto.GT
}

func (g *gt) GetPairing() crypto.Pairing {
	return g.p
}

func (g *gt) SetInfinity() {
	g.v.SetInt64(1)
}

func (g *gt) IsInfinity() bool {
	return g.v.IsOne()
}

var gtTable = map[int64][2]int64{
	0:  {1, 0},
	1:  {7, 28},
	2:  {97, 89},
	3:  {38, 6},
	4:  {31, 96},
	5:  {93, 25},
	6:  {59, 52},
	7:  {26, 97},
	8:  {2, 94},
	9:  {2, 7},
	10: {26, 4},
	11: {59, 49},
	12: {93, 76},
	13: {31, 5},
	14: {38, 95},
	15: {97, 12},
	16: {7, 73},
}
