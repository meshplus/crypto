package common

import (
	"math/big"

	"github.com/meshplus/crypto"
)

type CSForKeyTest struct {
	Sys crypto.Pairing
}

func (C *CSForKeyTest) Marshal() []byte {
	return nil
}

func (C *CSForKeyTest) Unmarshal(bytes []byte) ([]byte, error) {
	return nil, nil
}

func (C *CSForKeyTest) ComputeInC(cPath, info string) (wits []*big.Rat, err error) {
	panic("need implement")
}

func (C *CSForKeyTest) GetSignalByID(nowid int) (id, reoffset int, prefix string, value crypto.FieldElement) {
	switch nowid {
	case 0:
		return nowid, 0, "one", C.Sys.NewScalar().SetInt64(1)
	case 1:
		return nowid, 0, "x", nil
	case 2:
		return nowid, 0, "out", C.Sys.NewScalar().SetInt64(35)
	case 3:
		return nowid, 0, "sym1", nil
	case 4:
		return nowid, 0, "y", nil
	case 5:
		return nowid, 0, "sym2", nil
	default:
		return -2, -1, "", nil
	}
}

func (C *CSForKeyTest) ConstraintsNum() uint64 {
	return 4
}

func (C *CSForKeyTest) Next(pos *int) (index int, a, b, c map[int]crypto.FieldElement) {
	*pos++
	switch *pos {
	case 1:
		return 0,
			map[int]crypto.FieldElement{1: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{1: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{3: C.Sys.NewScalar().SetOne()}
	case 2:
		return 1,
			map[int]crypto.FieldElement{3: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{1: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{4: C.Sys.NewScalar().SetOne()}
	case 3:
		return 2,
			map[int]crypto.FieldElement{1: C.Sys.NewScalar().SetOne(), 4: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{0: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{5: C.Sys.NewScalar().SetOne()}
	case 4:
		return 3,
			map[int]crypto.FieldElement{0: C.Sys.NewScalar().SetInt64(5), 5: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{0: C.Sys.NewScalar().SetOne()},
			map[int]crypto.FieldElement{2: C.Sys.NewScalar().SetOne()}
	}
	return -1, nil, nil, nil
}

//1 x out; sym1 y sym2   这个case中，x看做输出，和out看做公开输入，没有隐私输入
//m=6, l=3
func (C *CSForKeyTest) SignalNum() int {
	return 6
}

func (C *CSForKeyTest) InputNum() (privateInput, publicInput int) {
	return 0, 1 //out
}

func (C *CSForKeyTest) OutputNum() int {
	return 1 //x
}

func (C *CSForKeyTest) Compute(_ string) ([]crypto.FieldElement, error) {
	return []crypto.FieldElement{
		C.Sys.NewScalar().SetOne(),
		C.Sys.NewScalar().SetInt64(3),
		C.Sys.NewScalar().SetInt64(35),
		C.Sys.NewScalar().SetInt64(9),
		C.Sys.NewScalar().SetInt64(27),
		C.Sys.NewScalar().SetInt64(30),
	}, nil
}

func (C *CSForKeyTest) String() string {
	return ""
}

func (C *CSForKeyTest) GetPairing() crypto.Pairing {
	return C.Sys
}
