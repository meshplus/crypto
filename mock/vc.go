// Code generated by MockGen. DO NOT EDIT.
// Source: vc.go

// Package crypto is a generated GoMock package.
package crypto

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	crypto "github.com/meshplus/crypto"
)

// MockChainSDK is a mock of ChainSDK interface.
type MockChainSDK struct {
	ctrl     *gomock.Controller
	recorder *MockChainSDKMockRecorder
}

// MockChainSDKMockRecorder is the mock recorder for MockChainSDK.
type MockChainSDKMockRecorder struct {
	mock *MockChainSDK
}

// NewMockChainSDK creates a new mock instance.
func NewMockChainSDK(ctrl *gomock.Controller) *MockChainSDK {
	mock := &MockChainSDK{ctrl: ctrl}
	mock.recorder = &MockChainSDKMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockChainSDK) EXPECT() *MockChainSDKMockRecorder {
	return m.recorder
}

// ChainType mocks base method.
func (m *MockChainSDK) ChainType() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ChainType")
	ret0, _ := ret[0].(string)
	return ret0
}

// ChainType indicates an expected call of ChainType.
func (mr *MockChainSDKMockRecorder) ChainType() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ChainType", reflect.TypeOf((*MockChainSDK)(nil).ChainType))
}

// InvokeFinish mocks base method.
func (m *MockChainSDK) InvokeFinish(nodes []string, address, taskID, proof, result, err string) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "InvokeFinish", nodes, address, taskID, proof, result, err)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// InvokeFinish indicates an expected call of InvokeFinish.
func (mr *MockChainSDKMockRecorder) InvokeFinish(nodes, address, taskID, proof, result, err interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "InvokeFinish", reflect.TypeOf((*MockChainSDK)(nil).InvokeFinish), nodes, address, taskID, proof, result, err)
}

// RegisterListening mocks base method.
func (m *MockChainSDK) RegisterListening(proxyAddress, businessAddress []string) (chan *crypto.Event, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RegisterListening", proxyAddress, businessAddress)
	ret0, _ := ret[0].(chan *crypto.Event)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RegisterListening indicates an expected call of RegisterListening.
func (mr *MockChainSDKMockRecorder) RegisterListening(proxyAddress, businessAddress interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RegisterListening", reflect.TypeOf((*MockChainSDK)(nil).RegisterListening), proxyAddress, businessAddress)
}

// UnregisterListening mocks base method.
func (m *MockChainSDK) UnregisterListening(address string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UnregisterListening", address)
	ret0, _ := ret[0].(error)
	return ret0
}

// UnregisterListening indicates an expected call of UnregisterListening.
func (mr *MockChainSDKMockRecorder) UnregisterListening(address interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UnregisterListening", reflect.TypeOf((*MockChainSDK)(nil).UnregisterListening), address)
}
