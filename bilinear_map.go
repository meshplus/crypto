package crypto

import (
	"errors"
	"io"
	"math/big"
	"sync"
)

//Position position in Pairing
type Position int

// Position in Pairing
const (
	G1 Position = 1 << iota
	G2
	GT
)

//FieldElement in Montgomery From
type FieldElement interface {
	UnmarshalJSON([]byte) error
	MarshalJSON() ([]byte, error)
	Add(a1, a2 FieldElement) FieldElement
	Double(FieldElement) FieldElement
	Sub(a1, a2 FieldElement) FieldElement
	Neg(FieldElement) FieldElement
	Mul(a1, a2 FieldElement) FieldElement
	Square(FieldElement) FieldElement
	Div(a1, a2 FieldElement) FieldElement
	Inv(FieldElement) FieldElement
	Exp(FieldElement, []byte) FieldElement

	Equal(FieldElement) bool
	IsZero() bool
	IsOne() bool
	IsNeg() bool

	Set(FieldElement) FieldElement
	SetOne() FieldElement
	SetZero() FieldElement
	SetInt64(int64) FieldElement
	SetUint64(uint64) FieldElement
	SetRandom(io.Reader) FieldElement

	// From sets self to v (regular form) and returns self (Montgomery form)
	From(rat *big.Int) FieldElement
	//Regular append regular bytes to 'in', keep 'z' unchanged
	Regular(in []byte) []byte
	//FromRegular interprets 'content' as the bytes of a big-endian unsigned integer,
	// sets z to that value (in Montgomery form), and returns z.
	FromRegular(content []byte) FieldElement

	//MontBytes set and return 'res' with bytes in Montgomery form
	MontBytes(res []byte) []byte

	//GetModule set 'b' to 21888242871839275222246405745257275088548364400416034343698204186575808495617
	GetModule(*big.Int)
	String() string
	//Copy get a clone
	Copy() FieldElement
}

//Point elliptic point
type Point interface {
	Marshaller
	Add(Point, Point) Point
	Set(Point) Point
	Double(Point) Point
	//Neg neg
	Neg(Point) Point
	ScalarMult(Point, *big.Int) Point //scalar is at Z+
	ScalarBaseMult(*big.Int) Point
	//GetPosition get position
	GetPosition() Position
	GetPairing() Pairing
	SetInfinity()
	IsInfinity() bool
}

//ErrFFT not support fft
var ErrFFT = errors.New("not support fft")

//AlgebraicSys algebra system
type AlgebraicSys interface {
	Marshaller
	GetModule() *big.Int
	Name() string
	NewScalar() FieldElement //fr
	//NewField() FieldElement  //fp
	PutScalar(FieldElement)
	GetRootOfUnity(uint64) (FieldElement, uint64, error)
}

//Pairing pairing of elliptic
type Pairing interface {
	AlgebraicSys
	Pair([]Point, []Point) Point
	PairCheck(P []Point, Q []Point) bool
	IsOnCurve(Point) error
	//GetBase never change result's value for GetBase, GetModule and GetOlder!
	GetBase(Position) Point
	NewPoint(Position) Point
	BatchScalarMultiplicationG1(scalars []*big.Int, ret []Point)
	BatchScalarMultiplicationG2(scalars []*big.Int, ret []Point)
}

//Marshaller marshal and unmarshal
type Marshaller interface {
	Marshal() []byte
	Unmarshal([]byte) ([]byte, error)
}

var bigPool = sync.Pool{
	New: func() interface{} {
		return new(big.Int)
	},
}

//GetBigInt get *big.Int
func GetBigInt() *big.Int {
	return bigPool.Get().(*big.Int)
}

//PutBigInt put *big.Int
func PutBigInt(in *big.Int) {
	if in == nil {
		return
	}
	in.SetInt64(0)
	bigPool.Put(in)
}
