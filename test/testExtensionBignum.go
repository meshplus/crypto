package common

import (
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"math/big"

	"github.com/meshplus/crypto"
)

func init() {
	gob.Register(&XBigNumForTest{})
}

//NewXBigNum new big number
func NewXBigNum(P, I, V, Vi *big.Int) *XBigNumForTest {
	ret := &XBigNumForTest{
		V:  V,
		Vi: Vi,
	}
	ret.P.Set(P)
	ret.IS.Set(I)
	return ret
}

//XBigNumForTest for test
type XBigNumForTest struct {
	P  big.Int
	IS big.Int
	V  *big.Int
	Vi *big.Int
}

func convertToX(in crypto.FieldElement, s *big.Int) *XBigNumForTest {
	switch a := in.(type) {
	case *BigNumForTest:
		return NewXBigNum(&a.P, s, new(big.Int).Set(a.V), new(big.Int))
	case *XBigNumForTest:
		return NewXBigNum(&a.P, s, new(big.Int).Set(a.V), new(big.Int).Set(a.Vi))
	default:
		panic("wrong state")
	}
}

//UnmarshalJSON json.UnMarshaler
func (b *XBigNumForTest) UnmarshalJSON(in []byte) error {
	return json.Unmarshal(in, b)
}

//MarshalJSON json.Marshaler
func (b *XBigNumForTest) MarshalJSON() ([]byte, error) {
	return json.Marshal(*b)
}

//MontBytes Montgomery Byte String
func (b *XBigNumForTest) MontBytes(res []byte) []byte {
	ret := b.Regular(nil)
	copy(res, ret)
	return res
}

//FromMont from Montgomery Bytes
func (b *XBigNumForTest) FromMont(bytes []byte) crypto.FieldElement {
	return b.FromRegular(bytes)
}

//Add add
func (b *XBigNumForTest) Add(a1, a2 crypto.FieldElement) crypto.FieldElement {
	in1, in2 := convertToX(a1, &iSquare), convertToX(a2, &iSquare)
	b.V.Add(in1.V, in2.V).Mod(b.V, &b.P)
	b.Vi.Add(in1.Vi, in2.Vi).Mod(b.Vi, &b.P)
	return b
}

//ToBigInt convert to big.Rat
func (b *XBigNumForTest) ToBigInt(rat *big.Int) *big.Int {
	b.V.Mod(b.V, &b.P)
	rat.Set(b.V)
	return b.V
}

//String fmt.Stringer
func (b *XBigNumForTest) String() string {
	return fmt.Sprintf("%v+%vi", b.V.Text(10), b.Vi.Text(10))
}

//Mul (V1·V2+IS·Vi1·Vi2, V1·Vi2+V2·Vi1)
func (b *XBigNumForTest) Mul(a1, a2 crypto.FieldElement) crypto.FieldElement {
	in1, in2 := convertToX(a1, &iSquare), convertToX(a2, &iSquare)
	t1, t2, t3 := new(big.Int), new(big.Int), new(big.Int)
	t1.Mul(in1.V, in2.V)
	t2.Mul(in1.Vi, in2.Vi)
	t2.Mul(t2, &b.IS)
	t1.Add(t1, t2)
	t1.Mod(t1, &b.P)

	t2.Mul(in1.V, in2.Vi)
	t3.Mul(in1.Vi, in2.V)
	t2.Add(t2, t3)
	t2.Mod(t2, &b.P)

	b.V.Set(t1)
	b.Vi.Set(t2)
	return b
}

//Square square
func (b *XBigNumForTest) Square(a crypto.FieldElement) crypto.FieldElement {
	return b.Mul(a, a)
}

//Double double
func (b *XBigNumForTest) Double(a crypto.FieldElement) crypto.FieldElement {
	return b.Add(a, a)
}

//Neg neg
func (b *XBigNumForTest) Neg(a crypto.FieldElement) crypto.FieldElement {
	in := convertToX(a, &iSquare)
	b.V.Neg(in.V).Mod(b.V, &b.P)
	b.Vi.Neg(in.Vi).Mod(b.Vi, &b.P)
	return b
}

//Inv inv
func (b *XBigNumForTest) Inv(a crypto.FieldElement) crypto.FieldElement {
	in := convertToX(a, &iSquare)
	t1, t2 := new(big.Int), new(big.Int)
	t1.Mul(in.V, in.V)
	t2.Mul(in.Vi, in.Vi)
	t2.Mul(t2, &b.IS)
	t1.Sub(t1, t2)
	t1.ModInverse(t1, &b.P) // 1/(a^2-b^2·IS)

	b.Vi.Neg(in.Vi)
	b.Vi.Mul(b.Vi, t1)
	b.V.Mul(in.V, t1)
	return b
}

//Sub sub
func (b *XBigNumForTest) Sub(a1, a2 crypto.FieldElement) crypto.FieldElement {
	tmp := NewXBigNum(&b.P, &b.IS, new(big.Int), new(big.Int))
	tmp.Set(a2)
	tmp.Neg(tmp)
	b.Add(a1, tmp)
	return b
}

//Div div
func (b *XBigNumForTest) Div(a1, a2 crypto.FieldElement) crypto.FieldElement {
	tmp := NewXBigNum(&b.P, &b.IS, new(big.Int), new(big.Int))
	tmp.Set(a2)
	tmp.Inv(tmp)
	b.Mul(a1, tmp)
	return b
}

//Exp exp
func (b *XBigNumForTest) Exp(element crypto.FieldElement, bytes []byte) crypto.FieldElement {
	e := new(big.Int).SetBytes(bytes)
	e.Mod(e, &module)
	ee := e.Int64()
	if ee == 0 {
		b.V.SetInt64(1)
		b.Vi.SetInt64(0)
		return b
	}
	ret := element.Copy()
	for i := int64(1); i < ee; i++ {
		ret.Mul(ret, element)
	}
	b.Set(ret)
	return b
}

//Equal is equal
func (b *XBigNumForTest) Equal(element crypto.FieldElement) bool {
	in := convertToX(element, &iSquare)
	return b.V.Cmp(in.V) == 0 && b.Vi.Cmp(in.Vi) == 0 &&
		b.P.Cmp(&in.P) == 0 && b.IS.Cmp(&in.IS) == 0
}

//IsZero is zero
func (b *XBigNumForTest) IsZero() bool {
	return b.V.Cmp(big.NewInt(0)) == 0 && b.Vi.Cmp(big.NewInt(0)) == 0
}

//IsOne is one
func (b *XBigNumForTest) IsOne() bool {
	return b.V.Cmp(one) == 0 && b.Vi.BitLen() == 0
}

//IsNegOne is neg one
func (b *XBigNumForTest) IsNegOne() bool {
	p := new(big.Int).Set(&b.P)
	p.Sub(p, one)
	b.V.Mod(b.V, &b.P)
	return b.V.Cmp(p) == 0 && b.Vi.BitLen() == 0
}

//IsNeg is negative
func (b *XBigNumForTest) IsNeg() bool {
	panic("need implement")
}

//Set set
func (b *XBigNumForTest) Set(element crypto.FieldElement) crypto.FieldElement {
	in := convertToX(element, &iSquare)
	b.V.Set(in.V)
	b.Vi.Set(in.Vi)
	b.IS.Set(&in.IS)
	b.P.Set(&in.P)
	return b
}

//SetOne set one
func (b *XBigNumForTest) SetOne() crypto.FieldElement {
	b.V.SetUint64(1)
	b.Vi.SetUint64(0)
	return b
}

//SetZero set zero
func (b *XBigNumForTest) SetZero() crypto.FieldElement {
	b.V.SetUint64(0)
	b.Vi.SetUint64(0)
	return b
}

//Copy copy
func (b *XBigNumForTest) Copy() crypto.FieldElement {
	tmp := &XBigNumForTest{
		V:  big.NewInt(0),
		Vi: big.NewInt(0),
	}
	tmp.Set(b)
	return tmp
}

//SetInt64 set uint64
func (b *XBigNumForTest) SetInt64(u int64) crypto.FieldElement {
	b.V.SetInt64(u)
	b.V.Mod(b.V, &b.P)
	b.Vi.SetInt64(0)
	return b
}

//SetUint64 set uint64
func (b *XBigNumForTest) SetUint64(u uint64) crypto.FieldElement {
	b.V.SetUint64(u)
	b.V.Mod(b.V, &b.P)
	b.Vi.SetInt64(0)
	return b
}

//SetRandom set random
func (b *XBigNumForTest) SetRandom(reader io.Reader) crypto.FieldElement {
	a, _ := rand.Int(reader, &b.P)
	b.V.Set(a)
	a, _ = rand.Int(reader, &b.P)
	b.Vi.Set(a)
	return b
}

//Regular regular
func (b *XBigNumForTest) Regular(bytes []byte) []byte {
	panic("need implement")
}

// FromRegular From regular
func (b *XBigNumForTest) FromRegular(content []byte) crypto.FieldElement {
	panic("need implement")
}

//From parse *big.Rat
func (b *XBigNumForTest) From(in *big.Int) crypto.FieldElement {
	panic("can't use")
}

//GetModule get module
func (b *XBigNumForTest) GetModule(b2 *big.Int) {
	b2.Set(&b.P)
}
