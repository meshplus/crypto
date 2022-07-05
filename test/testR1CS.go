package common

import (
	"testing"

	"github.com/meshplus/crypto"
)

//R1csForTest r1cs
type R1csForTest struct {
	L, R, O []map[int]crypto.FieldElement
}

//GetSignalByID get signal by ID
func (r *R1csForTest) GetSignalByID(nowid int) (id, reoffset int, prefix string, value crypto.FieldElement) {
	panic("implement me")
}

//NextVariable next Variable
func (r *R1csForTest) NextVariable(buf []crypto.FieldElement) (int, []crypto.FieldElement) {
	panic("implement me")
}

//ConstraintsNum constraints number
func (r *R1csForTest) ConstraintsNum() uint64 {
	return uint64(len(r.L))
}

//Next next
func (r *R1csForTest) Next(pos *int) (index int, a, b, c map[int]crypto.FieldElement) {
	*pos++
	if *pos == len(r.L) {
		return -1, nil, nil, nil
	}
	return *pos, r.L[*pos], r.R[*pos], r.O[*pos] //todo ?? r.pos -1
}

//GetR1CSForTest get r1cs
func GetR1CSForTest(t *testing.T, L, R, O [] /*N*/ [] /*M*/ crypto.FieldElement) crypto.R1CSIterator {
	if len(L) != len(R) || len(R) != len(O) {
		t.Fatalf("length of L, R, O is diffrient")
	}
	N, M := len(L), len(L[0])
	ret := &R1csForTest{
		L: make([]map[int]crypto.FieldElement, N),
		R: make([]map[int]crypto.FieldElement, N),
		O: make([]map[int]crypto.FieldElement, N),
	}
	for i := 0; i < N; i++ {
		ret.L[i] = make(map[int]crypto.FieldElement, M)
		ret.R[i] = make(map[int]crypto.FieldElement, M)
		ret.O[i] = make(map[int]crypto.FieldElement, M)
		for j := 0; j < M; j++ {
			if L[i][j] != nil && !L[i][j].IsZero() {
				(ret.L[i])[j] = L[i][j]
			}
			if R[i][j] != nil && !R[i][j].IsZero() {
				(ret.R[i])[j] = R[i][j]
			}
			if O[i][j] != nil && !O[i][j].IsZero() {
				(ret.O[i])[j] = O[i][j]
			}
		}
	}
	return ret
}
