package common

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io"
	"math/big"

	"github.com/meshplus/crypto"
)

func init() {
	gob.Register(&BigNumForTest{})
}

//NewBigNum new big
func NewBigNum(P, V *big.Int) *BigNumForTest {
	ret := &BigNumForTest{
		V: V,
	}
	ret.P.Set(P)
	return ret
}

//BigNumForTest for test
type BigNumForTest struct {
	P big.Int
	V *big.Int
}

//UnmarshalJSON json.UnMarshaler
func (b *BigNumForTest) UnmarshalJSON(in []byte) error {
	in = in[1 : len(in)-1]
	tmp := bytes.Split(in, []byte{'@'})
	if len(tmp) < 2 {
		return fmt.Errorf("format error, expect \"v@p\"")
	}
	v, p := tmp[0], tmp[1]
	b.P.SetString(string(p), 10)
	b.V, _ = new(big.Int).SetString(string(v), 10)
	return nil
}

//MarshalJSON json.Marshaler
//"v@p"
func (b *BigNumForTest) MarshalJSON() ([]byte, error) {
	var buf = bytes.NewBuffer(nil)
	buf.WriteRune('"')
	buf.WriteString(b.V.String())
	buf.WriteRune('@')
	buf.WriteString(b.P.String())
	buf.WriteRune('"')
	return buf.Bytes(), nil
}

//MontBytes Montgomery Byte String
func (b *BigNumForTest) MontBytes(bytes []byte) []byte {
	ret := b.Regular(nil)
	copy(bytes, ret)
	return bytes
}

//FromMont from Montgomery Bytes
func (b *BigNumForTest) FromMont(bytes []byte) crypto.FieldElement {
	return b.FromRegular(bytes)
}

//Add add
func (b *BigNumForTest) Add(a1, a2 crypto.FieldElement) crypto.FieldElement {
	b.V.Add(a1.(*BigNumForTest).V, a2.(*BigNumForTest).V).Mod(b.V, &b.P)
	return b
}

//ToBigInt convert to big.Rat
func (b *BigNumForTest) ToBigInt(rat *big.Int) *big.Int {
	b.V.Mod(b.V, &b.P)
	rat.Set(b.V)
	return b.V
}

//String fmt.Stringer
func (b *BigNumForTest) String() string {
	return b.V.Text(10)
}

//Mul mul
func (b *BigNumForTest) Mul(a1, a2 crypto.FieldElement) crypto.FieldElement {
	b.V.Mul(a1.(*BigNumForTest).V, a2.(*BigNumForTest).V).Mod(b.V, &b.P)
	return b
}

//Square square
func (b *BigNumForTest) Square(a crypto.FieldElement) crypto.FieldElement {
	b.V.Mul(a.(*BigNumForTest).V, a.(*BigNumForTest).V)
	b.V.Mod(b.V, &b.P)
	return b
}

//Double double
func (b *BigNumForTest) Double(a crypto.FieldElement) crypto.FieldElement {
	b.V.Add(a.(*BigNumForTest).V, a.(*BigNumForTest).V).Mod(b.V, &b.P)
	return b
}

//Neg neg
func (b *BigNumForTest) Neg(a crypto.FieldElement) crypto.FieldElement {
	b.V.Neg(a.(*BigNumForTest).V).Mod(b.V, &b.P)
	return b
}

//Inv inv
func (b *BigNumForTest) Inv(a crypto.FieldElement) crypto.FieldElement {
	b.V.ModInverse(a.(*BigNumForTest).V, &b.P)
	return b
}

//Sub sub
func (b *BigNumForTest) Sub(a1, a2 crypto.FieldElement) crypto.FieldElement {
	b.V.Sub(a1.(*BigNumForTest).V, a2.(*BigNumForTest).V).Mod(b.V, &b.P)
	return b
}

//Div div
func (b *BigNumForTest) Div(a1, a2 crypto.FieldElement) crypto.FieldElement {
	t := new(big.Int)
	if a2.IsZero() {
		panic("div by zero")
	}
	t.ModInverse(a2.(*BigNumForTest).V, &b.P)
	b.V.Mul(a1.(*BigNumForTest).V, t)
	b.V.Mod(b.V, &b.P)
	return b
}

//Exp exp
func (b *BigNumForTest) Exp(element crypto.FieldElement, bytes []byte) crypto.FieldElement {
	b.V.Exp(element.(*BigNumForTest).V, new(big.Int).SetBytes(bytes), &b.P)
	return b
}

//Equal reutrn bool
func (b *BigNumForTest) Equal(element crypto.FieldElement) bool {
	return b.V.Cmp(element.(*BigNumForTest).V) == 0
}

//IsZero is zero
func (b *BigNumForTest) IsZero() bool {
	return b.V.Sign() == 0
}

//IsNeg is negative
func (b *BigNumForTest) IsNeg() bool {
	p := new(big.Int).Set(&b.P)
	p.Rsh(p, 1)
	return b.V.Cmp(p) > 0 //  严格大于p/2,
}

//IsOne is one
func (b *BigNumForTest) IsOne() bool {
	return b.V.Cmp(big.NewInt(1)) == 0
}

//IsNegOne is neg one
func (b *BigNumForTest) IsNegOne() bool {
	p := new(big.Int).Set(&b.P)
	p.Sub(p, one)
	b.V.Mod(b.V, &b.P)
	return b.V.Cmp(p) == 0
}

//Set set value
func (b *BigNumForTest) Set(element crypto.FieldElement) crypto.FieldElement {
	o := element.(*BigNumForTest)
	b.P.Set(&o.P)
	b.V.Set(o.V)
	return b
}

//SetOne set one
func (b *BigNumForTest) SetOne() crypto.FieldElement {
	b.V.SetUint64(1)
	return b
}

//SetZero set zero
func (b *BigNumForTest) SetZero() crypto.FieldElement {
	b.V.SetUint64(0)
	return b
}

//Copy copy
func (b *BigNumForTest) Copy() crypto.FieldElement {
	tmp := new(BigNumForTest)
	tmp.V = new(big.Int)
	tmp.Set(b)
	return tmp
}

//SetInt64 set int64
func (b *BigNumForTest) SetInt64(u int64) crypto.FieldElement {
	b.V.SetInt64(u)
	b.V.Mod(b.V, &b.P)
	return b
}

//SetUint64 set uint64
func (b *BigNumForTest) SetUint64(u uint64) crypto.FieldElement {
	b.V.SetUint64(u)
	b.V.Mod(b.V, &b.P)
	return b
}

//SetRandom set random
func (b *BigNumForTest) SetRandom(reader io.Reader) crypto.FieldElement {
	a, _ := rand.Int(reader, &b.P)
	for a.BitLen() == 0 {
		a, _ = rand.Int(reader, &b.P)
	}
	b.V.Set(a)
	b.V.Mod(b.V, &b.P)
	return b
}

//Regular regular
func (b *BigNumForTest) Regular(bytes []byte) []byte {
	return append(bytes, b.V.Bytes()...)
}

// FromRegular From regular
func (b *BigNumForTest) FromRegular(content []byte) crypto.FieldElement {
	b.P.Set(&order)
	b.V = new(big.Int).SetBytes(content)
	return b
}

//From From
func (b *BigNumForTest) From(in *big.Int) crypto.FieldElement {
	b.V.Set(in)
	b.V.Mod(b.V, &b.P)
	return b
}

//GetModule get module
func (b *BigNumForTest) GetModule(b2 *big.Int) {
	b2.Set(&b.P)
}
