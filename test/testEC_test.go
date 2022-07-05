package common

import (
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCurveP101(t *testing.T) {
	subGroup := `INFINITY(1,2,1)(68,74,2)(26,45,3)(65,98,4)(12,32,5)(32,42,6)(91,35,7)(18,49,8)(18,52,9)(91,66,10)(32,59,11)(12,69,12)(65,3,13)(26,56,14)(68,27,15)(1,99,16)`
	curve := &Curve{
		A:  NewBigNum(&module, big.NewInt(0)),
		B:  NewBigNum(&module, big.NewInt(3)),
		Gx: NewBigNum(&module, big.NewInt(1)),
		Gy: NewBigNum(&module, big.NewInt(2)),
	}
	curve.Module.Set(&module)
	curve.Older.Set(&order)
	curve.Square.Set(&iSquare)

	t.Run("is on curve", func(t *testing.T) {
		G1 := curve.NewCurvePoint(one)
		G2 := curve.NewCurvePoint(one)
		G2.Double(G2)
		assert.True(t, curve.IsOnCurve(G2) == nil)
		assert.Equal(t, string(G2.Marshal()), "(68,74,2)")
		G1.Add(G1, G2)
		assert.True(t, curve.IsOnCurve(G1) == nil)
		assert.Equal(t, string(G1.Marshal()), "(26,45,3)")
	})

	t.Run("add cycle", func(t *testing.T) {
		G := curve.NewCurvePoint(one)
		T := curve.NewCurvePoint(nil)
		target := ""
		for i := 0; i < 17; i++ {
			target += string(T.Marshal())
			T.Add(T, G)
		}
		assert.Equal(t, subGroup, target)
	})

	t.Run("mul base", func(t *testing.T) {
		E, T := new(big.Int), new(big.Int)
		E.SetInt64(1)
		G := curve.NewCurvePoint(one)
		var target strings.Builder
		for i := 0; i < 17; i++ {
			G.ScalarBaseMult(T)
			target.Write(G.Marshal())
			T.Add(T, E)
		}
		assert.Equal(t, subGroup, target.String())
	})

	t.Run("double cycle", func(t *testing.T) {
		G := curve.NewCurvePoint(one)
		//(1,2) (68,74) (65,98) (18,49) (1,99) (68,27) (65,3) (18,52) (1,2)
		//1 2 4 8 16 15 13 9 1
		for i := 0; i < 8; i++ {
			G.Double(G)
		}
		assert.Equal(t, "(1,2,1)", string(G.Marshal()))
	})
}

func TestTwistP101(t *testing.T) {
	subGroup := `INFINITY(36,0+31u)(90,0+82u)(10,0+16u)(63,0+35u)(74,0+12u)(41,0+22u)(66,0+23u)(2,0+34u)` +
		`(2,0+67u)(66,0+78u)(41,0+79u)(74,0+89u)(63,0+66u)(10,0+85u)(90,0+19u)(36,0+70u)`
	curve := &Curve{
		A:   NewBigNum(&module, big.NewInt(0)),
		B:   NewBigNum(&module, big.NewInt(3)),
		Gx:  NewBigNum(&module, big.NewInt(1)),
		Gy:  NewBigNum(&module, big.NewInt(2)),
		G2x: NewXBigNum(&module, &iSquare, big.NewInt(36), big.NewInt(0)),
		G2y: NewXBigNum(&module, &iSquare, big.NewInt(0), big.NewInt(31)),
	}
	curve.Module.Set(&module)
	curve.Older.Set(&order)
	curve.Square.Set(&iSquare)
	t.Run("is on curve", func(t *testing.T) {
		G1 := curve.NewTwistPoint(one)
		G2 := curve.NewTwistPoint(one)
		G2.Double(G2)
		assert.True(t, curve.IsOnCurve(G2) == nil)
		assert.Equal(t, string(G2.Marshal()), "(90,0+82u)")
		G1.Add(G1, G2)
		assert.True(t, curve.IsOnCurve(G1) == nil)
		assert.Equal(t, string(G1.Marshal()), "(10,0+16u)")
	})

	t.Run("add cycle", func(t *testing.T) {
		G := curve.NewTwistPoint(one)
		T := curve.NewTwistPoint(nil)
		target := ""
		for i := 0; i < 17; i++ {
			target += string(T.Marshal())
			T.Add(T, G)
		}
		assert.Equal(t, subGroup, target)
	})

	t.Run("mul base", func(t *testing.T) {
		E, T := new(big.Int), new(big.Int)
		E.SetInt64(1)
		G := curve.NewTwistPoint(one)
		target := ""
		for i := 0; i < 17; i++ {
			G.ScalarBaseMult(T)
			target += string(G.Marshal())
			T.Add(T, E)
		}
		assert.Equal(t, subGroup, target)
	})

	t.Run("double cycle", func(t *testing.T) {
		G := curve.NewTwistPoint(one)
		//1 2 4 8 16 15 13 9 1
		for i := 0; i < 8; i++ {
			G.Double(G)
		}
		assert.Equal(t, string(G.Marshal()), "(36,0+31u)")
	})
}

func TestPair(t *testing.T) {
	// This implements the tripartite Diffie-Hellman algorithm From "A One
	// Round Protocol for Tripartite Diffie-Hellman", A. Joux.
	// http://www.springerlink.com/content/cddc57yyva0hburb/fulltext.pdf

	// Each of three parties, a, b and c, generate a private value.
	t.Run("random", func(t *testing.T) {
		//aA,_ := rand.Int(rand.Reader, order)
		//aB,_ := rand.Int(rand.Reader, order)
		//aC,_ := rand.Int(rand.Reader, order)
		aA, aB, aC := big.NewInt(14), big.NewInt(3), big.NewInt(3)
		t.Logf("a:%v,b:%v,c:%v", aA.Text(10), aB.String(), aC.String())
		testPairing(t, aA, aB, aC)
	})

	tCase1 := [][]int64{{14, 3, 3}, {12, 12, 11}, {5, 13, 5}, {16, 15, 10}}
	for i := range tCase1 {
		t.Run("tCase1_"+strconv.Itoa(i), func(t *testing.T) {
			cases := tCase1[i]
			a, b, c := big.NewInt(cases[0]), big.NewInt(cases[1]), big.NewInt(cases[2])
			testPairing(t, a, b, c)
		})
	}
	tCase2 := [][]int64{{9, 15, 5}, {5, 3, 1}, {0, 0, 0}}
	for i := range tCase2 {
		t.Run("tCase2_"+strconv.Itoa(i), func(t *testing.T) {
			cases := tCase2[i]
			a, b, c := big.NewInt(cases[0]), big.NewInt(cases[1]), big.NewInt(cases[2])
			testPairing(t, a, b, c)
		})
	}
}

func testPairing(t *testing.T, a, b, c *big.Int) {
	Curve101 := GetCurve101(true).(*Curve)
	// Then each party calculates g₁ and g₂ times their private value.
	pa := Curve101.NewCurvePoint(a)
	qa := Curve101.NewTwistPoint(a)

	pb := Curve101.NewCurvePoint(b)
	qb := Curve101.NewTwistPoint(b)

	pc := Curve101.NewCurvePoint(c)
	qc := Curve101.NewTwistPoint(c)

	// Now each party exchanges its public values with the other two and
	// all parties can calculate the shared key.
	k1 := Curve101.pairing(pb, qc)
	k1.ScalarMult(k1, a)

	k2 := Curve101.pairing(pc, qa)
	k2.ScalarMult(k2, b)

	k3 := Curve101.pairing(pa, qb)
	k3.ScalarMult(k3, c)

	// k1, k2 and k3 will all be equal.
	assert.Equal(t, k1.Marshal(), k2.Marshal())
	assert.Equal(t, k1.Marshal(), k3.Marshal())
}
