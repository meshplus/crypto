// Code generated by MockGen. DO NOT EDIT.
// Source: bilinear_map.go

// Package crypto is a generated GoMock package.
package crypto

import (
	io "io"
	big "math/big"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	crypto "github.com/meshplus/crypto"
)

// MockFieldElement is a mock of FieldElement interface.
type MockFieldElement struct {
	ctrl     *gomock.Controller
	recorder *MockFieldElementMockRecorder
}

// MockFieldElementMockRecorder is the mock recorder for MockFieldElement.
type MockFieldElementMockRecorder struct {
	mock *MockFieldElement
}

// NewMockFieldElement creates a new mock instance.
func NewMockFieldElement(ctrl *gomock.Controller) *MockFieldElement {
	mock := &MockFieldElement{ctrl: ctrl}
	mock.recorder = &MockFieldElementMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockFieldElement) EXPECT() *MockFieldElementMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockFieldElement) Add(a1, a2 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", a1, a2)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockFieldElementMockRecorder) Add(a1, a2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockFieldElement)(nil).Add), a1, a2)
}

// Copy mocks base method.
func (m *MockFieldElement) Copy() crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Copy")
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Copy indicates an expected call of Copy.
func (mr *MockFieldElementMockRecorder) Copy() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Copy", reflect.TypeOf((*MockFieldElement)(nil).Copy))
}

// Div mocks base method.
func (m *MockFieldElement) Div(a1, a2 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Div", a1, a2)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Div indicates an expected call of Div.
func (mr *MockFieldElementMockRecorder) Div(a1, a2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Div", reflect.TypeOf((*MockFieldElement)(nil).Div), a1, a2)
}

// Double mocks base method.
func (m *MockFieldElement) Double(arg0 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Double", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Double indicates an expected call of Double.
func (mr *MockFieldElementMockRecorder) Double(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Double", reflect.TypeOf((*MockFieldElement)(nil).Double), arg0)
}

// Equal mocks base method.
func (m *MockFieldElement) Equal(arg0 crypto.FieldElement) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Equal", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// Equal indicates an expected call of Equal.
func (mr *MockFieldElementMockRecorder) Equal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Equal", reflect.TypeOf((*MockFieldElement)(nil).Equal), arg0)
}

// Exp mocks base method.
func (m *MockFieldElement) Exp(arg0 crypto.FieldElement, arg1 []byte) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Exp", arg0, arg1)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Exp indicates an expected call of Exp.
func (mr *MockFieldElementMockRecorder) Exp(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Exp", reflect.TypeOf((*MockFieldElement)(nil).Exp), arg0, arg1)
}

// From mocks base method.
func (m *MockFieldElement) From(rat *big.Int) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "From", rat)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// From indicates an expected call of From.
func (mr *MockFieldElementMockRecorder) From(rat interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "From", reflect.TypeOf((*MockFieldElement)(nil).From), rat)
}

// FromRegular mocks base method.
func (m *MockFieldElement) FromRegular(content []byte) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "FromRegular", content)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// FromRegular indicates an expected call of FromRegular.
func (mr *MockFieldElementMockRecorder) FromRegular(content interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FromRegular", reflect.TypeOf((*MockFieldElement)(nil).FromRegular), content)
}

// GetModule mocks base method.
func (m *MockFieldElement) GetModule(arg0 *big.Int) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "GetModule", arg0)
}

// GetModule indicates an expected call of GetModule.
func (mr *MockFieldElementMockRecorder) GetModule(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetModule", reflect.TypeOf((*MockFieldElement)(nil).GetModule), arg0)
}

// Inv mocks base method.
func (m *MockFieldElement) Inv(arg0 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Inv", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Inv indicates an expected call of Inv.
func (mr *MockFieldElementMockRecorder) Inv(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Inv", reflect.TypeOf((*MockFieldElement)(nil).Inv), arg0)
}

// IsNeg mocks base method.
func (m *MockFieldElement) IsNeg() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsNeg")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsNeg indicates an expected call of IsNeg.
func (mr *MockFieldElementMockRecorder) IsNeg() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsNeg", reflect.TypeOf((*MockFieldElement)(nil).IsNeg))
}

// IsOne mocks base method.
func (m *MockFieldElement) IsOne() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsOne")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsOne indicates an expected call of IsOne.
func (mr *MockFieldElementMockRecorder) IsOne() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOne", reflect.TypeOf((*MockFieldElement)(nil).IsOne))
}

// IsZero mocks base method.
func (m *MockFieldElement) IsZero() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsZero")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsZero indicates an expected call of IsZero.
func (mr *MockFieldElementMockRecorder) IsZero() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsZero", reflect.TypeOf((*MockFieldElement)(nil).IsZero))
}

// MarshalJSON mocks base method.
func (m *MockFieldElement) MarshalJSON() ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MarshalJSON")
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// MarshalJSON indicates an expected call of MarshalJSON.
func (mr *MockFieldElementMockRecorder) MarshalJSON() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MarshalJSON", reflect.TypeOf((*MockFieldElement)(nil).MarshalJSON))
}

// MontBytes mocks base method.
func (m *MockFieldElement) MontBytes(res []byte) []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "MontBytes", res)
	ret0, _ := ret[0].([]byte)
	return ret0
}

// MontBytes indicates an expected call of MontBytes.
func (mr *MockFieldElementMockRecorder) MontBytes(res interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "MontBytes", reflect.TypeOf((*MockFieldElement)(nil).MontBytes), res)
}

// Mul mocks base method.
func (m *MockFieldElement) Mul(a1, a2 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Mul", a1, a2)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Mul indicates an expected call of Mul.
func (mr *MockFieldElementMockRecorder) Mul(a1, a2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Mul", reflect.TypeOf((*MockFieldElement)(nil).Mul), a1, a2)
}

// Neg mocks base method.
func (m *MockFieldElement) Neg(arg0 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Neg", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Neg indicates an expected call of Neg.
func (mr *MockFieldElementMockRecorder) Neg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Neg", reflect.TypeOf((*MockFieldElement)(nil).Neg), arg0)
}

// Regular mocks base method.
func (m *MockFieldElement) Regular(in []byte) []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Regular", in)
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Regular indicates an expected call of Regular.
func (mr *MockFieldElementMockRecorder) Regular(in interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Regular", reflect.TypeOf((*MockFieldElement)(nil).Regular), in)
}

// Set mocks base method.
func (m *MockFieldElement) Set(arg0 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Set", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Set indicates an expected call of Set.
func (mr *MockFieldElementMockRecorder) Set(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Set", reflect.TypeOf((*MockFieldElement)(nil).Set), arg0)
}

// SetInt64 mocks base method.
func (m *MockFieldElement) SetInt64(arg0 int64) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetInt64", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// SetInt64 indicates an expected call of SetInt64.
func (mr *MockFieldElementMockRecorder) SetInt64(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetInt64", reflect.TypeOf((*MockFieldElement)(nil).SetInt64), arg0)
}

// SetOne mocks base method.
func (m *MockFieldElement) SetOne() crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetOne")
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// SetOne indicates an expected call of SetOne.
func (mr *MockFieldElementMockRecorder) SetOne() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetOne", reflect.TypeOf((*MockFieldElement)(nil).SetOne))
}

// SetRandom mocks base method.
func (m *MockFieldElement) SetRandom(arg0 io.Reader) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetRandom", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// SetRandom indicates an expected call of SetRandom.
func (mr *MockFieldElementMockRecorder) SetRandom(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetRandom", reflect.TypeOf((*MockFieldElement)(nil).SetRandom), arg0)
}

// SetUint64 mocks base method.
func (m *MockFieldElement) SetUint64(arg0 uint64) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetUint64", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// SetUint64 indicates an expected call of SetUint64.
func (mr *MockFieldElementMockRecorder) SetUint64(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetUint64", reflect.TypeOf((*MockFieldElement)(nil).SetUint64), arg0)
}

// SetZero mocks base method.
func (m *MockFieldElement) SetZero() crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "SetZero")
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// SetZero indicates an expected call of SetZero.
func (mr *MockFieldElementMockRecorder) SetZero() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetZero", reflect.TypeOf((*MockFieldElement)(nil).SetZero))
}

// Square mocks base method.
func (m *MockFieldElement) Square(arg0 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Square", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Square indicates an expected call of Square.
func (mr *MockFieldElementMockRecorder) Square(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Square", reflect.TypeOf((*MockFieldElement)(nil).Square), arg0)
}

// String mocks base method.
func (m *MockFieldElement) String() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "String")
	ret0, _ := ret[0].(string)
	return ret0
}

// String indicates an expected call of String.
func (mr *MockFieldElementMockRecorder) String() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "String", reflect.TypeOf((*MockFieldElement)(nil).String))
}

// Sub mocks base method.
func (m *MockFieldElement) Sub(a1, a2 crypto.FieldElement) crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Sub", a1, a2)
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// Sub indicates an expected call of Sub.
func (mr *MockFieldElementMockRecorder) Sub(a1, a2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Sub", reflect.TypeOf((*MockFieldElement)(nil).Sub), a1, a2)
}

// UnmarshalJSON mocks base method.
func (m *MockFieldElement) UnmarshalJSON(arg0 []byte) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnmarshalJSON", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// UnmarshalJSON indicates an expected call of UnmarshalJSON.
func (mr *MockFieldElementMockRecorder) UnmarshalJSON(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnmarshalJSON", reflect.TypeOf((*MockFieldElement)(nil).UnmarshalJSON), arg0)
}

// MockPoint is a mock of Point interface.
type MockPoint struct {
	ctrl     *gomock.Controller
	recorder *MockPointMockRecorder
}

// MockPointMockRecorder is the mock recorder for MockPoint.
type MockPointMockRecorder struct {
	mock *MockPoint
}

// NewMockPoint creates a new mock instance.
func NewMockPoint(ctrl *gomock.Controller) *MockPoint {
	mock := &MockPoint{ctrl: ctrl}
	mock.recorder = &MockPointMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPoint) EXPECT() *MockPointMockRecorder {
	return m.recorder
}

// Add mocks base method.
func (m *MockPoint) Add(arg0, arg1 crypto.Point) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Add", arg0, arg1)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// Add indicates an expected call of Add.
func (mr *MockPointMockRecorder) Add(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Add", reflect.TypeOf((*MockPoint)(nil).Add), arg0, arg1)
}

// Double mocks base method.
func (m *MockPoint) Double(arg0 crypto.Point) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Double", arg0)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// Double indicates an expected call of Double.
func (mr *MockPointMockRecorder) Double(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Double", reflect.TypeOf((*MockPoint)(nil).Double), arg0)
}

// GetPairing mocks base method.
func (m *MockPoint) GetPairing() crypto.Pairing {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPairing")
	ret0, _ := ret[0].(crypto.Pairing)
	return ret0
}

// GetPairing indicates an expected call of GetPairing.
func (mr *MockPointMockRecorder) GetPairing() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPairing", reflect.TypeOf((*MockPoint)(nil).GetPairing))
}

// GetPosition mocks base method.
func (m *MockPoint) GetPosition() crypto.Position {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPosition")
	ret0, _ := ret[0].(crypto.Position)
	return ret0
}

// GetPosition indicates an expected call of GetPosition.
func (mr *MockPointMockRecorder) GetPosition() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPosition", reflect.TypeOf((*MockPoint)(nil).GetPosition))
}

// IsInfinity mocks base method.
func (m *MockPoint) IsInfinity() bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsInfinity")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsInfinity indicates an expected call of IsInfinity.
func (mr *MockPointMockRecorder) IsInfinity() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsInfinity", reflect.TypeOf((*MockPoint)(nil).IsInfinity))
}

// Marshal mocks base method.
func (m *MockPoint) Marshal() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Marshal")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Marshal indicates an expected call of Marshal.
func (mr *MockPointMockRecorder) Marshal() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Marshal", reflect.TypeOf((*MockPoint)(nil).Marshal))
}

// Neg mocks base method.
func (m *MockPoint) Neg(arg0 crypto.Point) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Neg", arg0)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// Neg indicates an expected call of Neg.
func (mr *MockPointMockRecorder) Neg(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Neg", reflect.TypeOf((*MockPoint)(nil).Neg), arg0)
}

// ScalarBaseMult mocks base method.
func (m *MockPoint) ScalarBaseMult(arg0 *big.Int) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ScalarBaseMult", arg0)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// ScalarBaseMult indicates an expected call of ScalarBaseMult.
func (mr *MockPointMockRecorder) ScalarBaseMult(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ScalarBaseMult", reflect.TypeOf((*MockPoint)(nil).ScalarBaseMult), arg0)
}

// ScalarMult mocks base method.
func (m *MockPoint) ScalarMult(arg0 crypto.Point, arg1 *big.Int) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ScalarMult", arg0, arg1)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// ScalarMult indicates an expected call of ScalarMult.
func (mr *MockPointMockRecorder) ScalarMult(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ScalarMult", reflect.TypeOf((*MockPoint)(nil).ScalarMult), arg0, arg1)
}

// Set mocks base method.
func (m *MockPoint) Set(arg0 crypto.Point) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Set", arg0)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// Set indicates an expected call of Set.
func (mr *MockPointMockRecorder) Set(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Set", reflect.TypeOf((*MockPoint)(nil).Set), arg0)
}

// SetInfinity mocks base method.
func (m *MockPoint) SetInfinity() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "SetInfinity")
}

// SetInfinity indicates an expected call of SetInfinity.
func (mr *MockPointMockRecorder) SetInfinity() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetInfinity", reflect.TypeOf((*MockPoint)(nil).SetInfinity))
}

// Unmarshal mocks base method.
func (m *MockPoint) Unmarshal(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unmarshal", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Unmarshal indicates an expected call of Unmarshal.
func (mr *MockPointMockRecorder) Unmarshal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unmarshal", reflect.TypeOf((*MockPoint)(nil).Unmarshal), arg0)
}

// MockAlgebraicSys is a mock of AlgebraicSys interface.
type MockAlgebraicSys struct {
	ctrl     *gomock.Controller
	recorder *MockAlgebraicSysMockRecorder
}

// MockAlgebraicSysMockRecorder is the mock recorder for MockAlgebraicSys.
type MockAlgebraicSysMockRecorder struct {
	mock *MockAlgebraicSys
}

// NewMockAlgebraicSys creates a new mock instance.
func NewMockAlgebraicSys(ctrl *gomock.Controller) *MockAlgebraicSys {
	mock := &MockAlgebraicSys{ctrl: ctrl}
	mock.recorder = &MockAlgebraicSysMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAlgebraicSys) EXPECT() *MockAlgebraicSysMockRecorder {
	return m.recorder
}

// GetModule mocks base method.
func (m *MockAlgebraicSys) GetModule() *big.Int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetModule")
	ret0, _ := ret[0].(*big.Int)
	return ret0
}

// GetModule indicates an expected call of GetModule.
func (mr *MockAlgebraicSysMockRecorder) GetModule() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetModule", reflect.TypeOf((*MockAlgebraicSys)(nil).GetModule))
}

// GetRootOfUnity mocks base method.
func (m *MockAlgebraicSys) GetRootOfUnity(arg0 uint64) (crypto.FieldElement, uint64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRootOfUnity", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	ret1, _ := ret[1].(uint64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetRootOfUnity indicates an expected call of GetRootOfUnity.
func (mr *MockAlgebraicSysMockRecorder) GetRootOfUnity(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRootOfUnity", reflect.TypeOf((*MockAlgebraicSys)(nil).GetRootOfUnity), arg0)
}

// Marshal mocks base method.
func (m *MockAlgebraicSys) Marshal() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Marshal")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Marshal indicates an expected call of Marshal.
func (mr *MockAlgebraicSysMockRecorder) Marshal() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Marshal", reflect.TypeOf((*MockAlgebraicSys)(nil).Marshal))
}

// Name mocks base method.
func (m *MockAlgebraicSys) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockAlgebraicSysMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockAlgebraicSys)(nil).Name))
}

// NewScalar mocks base method.
func (m *MockAlgebraicSys) NewScalar() crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewScalar")
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// NewScalar indicates an expected call of NewScalar.
func (mr *MockAlgebraicSysMockRecorder) NewScalar() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewScalar", reflect.TypeOf((*MockAlgebraicSys)(nil).NewScalar))
}

// PutScalar mocks base method.
func (m *MockAlgebraicSys) PutScalar(arg0 crypto.FieldElement) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PutScalar", arg0)
}

// PutScalar indicates an expected call of PutScalar.
func (mr *MockAlgebraicSysMockRecorder) PutScalar(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PutScalar", reflect.TypeOf((*MockAlgebraicSys)(nil).PutScalar), arg0)
}

// Unmarshal mocks base method.
func (m *MockAlgebraicSys) Unmarshal(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unmarshal", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Unmarshal indicates an expected call of Unmarshal.
func (mr *MockAlgebraicSysMockRecorder) Unmarshal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unmarshal", reflect.TypeOf((*MockAlgebraicSys)(nil).Unmarshal), arg0)
}

// MockPairing is a mock of Pairing interface.
type MockPairing struct {
	ctrl     *gomock.Controller
	recorder *MockPairingMockRecorder
}

// MockPairingMockRecorder is the mock recorder for MockPairing.
type MockPairingMockRecorder struct {
	mock *MockPairing
}

// NewMockPairing creates a new mock instance.
func NewMockPairing(ctrl *gomock.Controller) *MockPairing {
	mock := &MockPairing{ctrl: ctrl}
	mock.recorder = &MockPairingMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockPairing) EXPECT() *MockPairingMockRecorder {
	return m.recorder
}

// BatchScalarMultiplicationG1 mocks base method.
func (m *MockPairing) BatchScalarMultiplicationG1(scalars []*big.Int, ret []crypto.Point) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "BatchScalarMultiplicationG1", scalars, ret)
}

// BatchScalarMultiplicationG1 indicates an expected call of BatchScalarMultiplicationG1.
func (mr *MockPairingMockRecorder) BatchScalarMultiplicationG1(scalars, ret interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchScalarMultiplicationG1", reflect.TypeOf((*MockPairing)(nil).BatchScalarMultiplicationG1), scalars, ret)
}

// BatchScalarMultiplicationG2 mocks base method.
func (m *MockPairing) BatchScalarMultiplicationG2(scalars []*big.Int, ret []crypto.Point) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "BatchScalarMultiplicationG2", scalars, ret)
}

// BatchScalarMultiplicationG2 indicates an expected call of BatchScalarMultiplicationG2.
func (mr *MockPairingMockRecorder) BatchScalarMultiplicationG2(scalars, ret interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "BatchScalarMultiplicationG2", reflect.TypeOf((*MockPairing)(nil).BatchScalarMultiplicationG2), scalars, ret)
}

// GetBase mocks base method.
func (m *MockPairing) GetBase(arg0 crypto.Position) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBase", arg0)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// GetBase indicates an expected call of GetBase.
func (mr *MockPairingMockRecorder) GetBase(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBase", reflect.TypeOf((*MockPairing)(nil).GetBase), arg0)
}

// GetModule mocks base method.
func (m *MockPairing) GetModule() *big.Int {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetModule")
	ret0, _ := ret[0].(*big.Int)
	return ret0
}

// GetModule indicates an expected call of GetModule.
func (mr *MockPairingMockRecorder) GetModule() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetModule", reflect.TypeOf((*MockPairing)(nil).GetModule))
}

// GetRootOfUnity mocks base method.
func (m *MockPairing) GetRootOfUnity(arg0 uint64) (crypto.FieldElement, uint64, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRootOfUnity", arg0)
	ret0, _ := ret[0].(crypto.FieldElement)
	ret1, _ := ret[1].(uint64)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// GetRootOfUnity indicates an expected call of GetRootOfUnity.
func (mr *MockPairingMockRecorder) GetRootOfUnity(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRootOfUnity", reflect.TypeOf((*MockPairing)(nil).GetRootOfUnity), arg0)
}

// IsOnCurve mocks base method.
func (m *MockPairing) IsOnCurve(arg0 crypto.Point) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "IsOnCurve", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// IsOnCurve indicates an expected call of IsOnCurve.
func (mr *MockPairingMockRecorder) IsOnCurve(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsOnCurve", reflect.TypeOf((*MockPairing)(nil).IsOnCurve), arg0)
}

// Marshal mocks base method.
func (m *MockPairing) Marshal() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Marshal")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Marshal indicates an expected call of Marshal.
func (mr *MockPairingMockRecorder) Marshal() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Marshal", reflect.TypeOf((*MockPairing)(nil).Marshal))
}

// Name mocks base method.
func (m *MockPairing) Name() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Name")
	ret0, _ := ret[0].(string)
	return ret0
}

// Name indicates an expected call of Name.
func (mr *MockPairingMockRecorder) Name() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Name", reflect.TypeOf((*MockPairing)(nil).Name))
}

// NewPoint mocks base method.
func (m *MockPairing) NewPoint(arg0 crypto.Position) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewPoint", arg0)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// NewPoint indicates an expected call of NewPoint.
func (mr *MockPairingMockRecorder) NewPoint(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewPoint", reflect.TypeOf((*MockPairing)(nil).NewPoint), arg0)
}

// NewScalar mocks base method.
func (m *MockPairing) NewScalar() crypto.FieldElement {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewScalar")
	ret0, _ := ret[0].(crypto.FieldElement)
	return ret0
}

// NewScalar indicates an expected call of NewScalar.
func (mr *MockPairingMockRecorder) NewScalar() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewScalar", reflect.TypeOf((*MockPairing)(nil).NewScalar))
}

// Pair mocks base method.
func (m *MockPairing) Pair(arg0, arg1 []crypto.Point) crypto.Point {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pair", arg0, arg1)
	ret0, _ := ret[0].(crypto.Point)
	return ret0
}

// Pair indicates an expected call of Pair.
func (mr *MockPairingMockRecorder) Pair(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pair", reflect.TypeOf((*MockPairing)(nil).Pair), arg0, arg1)
}

// PairCheck mocks base method.
func (m *MockPairing) PairCheck(P, Q []crypto.Point) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PairCheck", P, Q)
	ret0, _ := ret[0].(bool)
	return ret0
}

// PairCheck indicates an expected call of PairCheck.
func (mr *MockPairingMockRecorder) PairCheck(P, Q interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PairCheck", reflect.TypeOf((*MockPairing)(nil).PairCheck), P, Q)
}

// PutScalar mocks base method.
func (m *MockPairing) PutScalar(arg0 crypto.FieldElement) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "PutScalar", arg0)
}

// PutScalar indicates an expected call of PutScalar.
func (mr *MockPairingMockRecorder) PutScalar(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PutScalar", reflect.TypeOf((*MockPairing)(nil).PutScalar), arg0)
}

// Unmarshal mocks base method.
func (m *MockPairing) Unmarshal(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unmarshal", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Unmarshal indicates an expected call of Unmarshal.
func (mr *MockPairingMockRecorder) Unmarshal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unmarshal", reflect.TypeOf((*MockPairing)(nil).Unmarshal), arg0)
}

// MockMarshaller is a mock of Marshaller interface.
type MockMarshaller struct {
	ctrl     *gomock.Controller
	recorder *MockMarshallerMockRecorder
}

// MockMarshallerMockRecorder is the mock recorder for MockMarshaller.
type MockMarshallerMockRecorder struct {
	mock *MockMarshaller
}

// NewMockMarshaller creates a new mock instance.
func NewMockMarshaller(ctrl *gomock.Controller) *MockMarshaller {
	mock := &MockMarshaller{ctrl: ctrl}
	mock.recorder = &MockMarshallerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockMarshaller) EXPECT() *MockMarshallerMockRecorder {
	return m.recorder
}

// Marshal mocks base method.
func (m *MockMarshaller) Marshal() []byte {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Marshal")
	ret0, _ := ret[0].([]byte)
	return ret0
}

// Marshal indicates an expected call of Marshal.
func (mr *MockMarshallerMockRecorder) Marshal() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Marshal", reflect.TypeOf((*MockMarshaller)(nil).Marshal))
}

// Unmarshal mocks base method.
func (m *MockMarshaller) Unmarshal(arg0 []byte) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Unmarshal", arg0)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Unmarshal indicates an expected call of Unmarshal.
func (mr *MockMarshallerMockRecorder) Unmarshal(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Unmarshal", reflect.TypeOf((*MockMarshaller)(nil).Unmarshal), arg0)
}