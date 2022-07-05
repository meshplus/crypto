package crypto

import (
	"fmt"
	"math/big"
)

//nolint
const (
	ST_ONE = 1 + iota
	ST_OUTPUT
	ST_PUBINPUT
	ST_PRVINPUT
	ST_INTERNAL  //除1、输入和输出外的骨干信号
	ST_DISCARDED //边缘信号，总是依附于某个骨干信号; 无用的信号
	ST_CONSTANT  //常量信号，即被赋值为N的信号
)

//zkp algo
const (
	Groth16        = 0x00
	AlgoTypeOffset = 32
)

//algo name
const (
	AlgoGroth16 = "groth16"
	AlgoPlonk   = "plonk"
)

// VerifyVersion1 version for evm unmarshal
const (
	VerifyVersion1 = 0x01 << iota
)

// ProofVersion1 version for proof unmarshal
const (
	ProofVersion1 = 0x01 << iota
)

//ChainType chain type
type ChainType string

//chain type enum
const (
	VMEvm       ChainType = "EVM"
	VMChainCode ChainType = "ChainCode"
)

//ProverInfo witness
type ProverInfo map[string][]*big.Int

//R1CSIterator r1cs iterator
type R1CSIterator interface {
	ConstraintsNum() uint64
	Next(pos *int) (index int, a, b, c map[int]FieldElement)
	GetSignalByID(nowid int) (id, reoffset int, prefix string, value FieldElement)
}

//R1CS r1cs
type R1CS interface {
	fmt.Stringer
	R1CSIterator
	SignalNum() int //m
	InputNum() (privateInput, publicInput int)
	OutputNum() int // l = publicInput + OutputNum() + 1 = m - privateInput
	Marshal() []byte
	GetPairing() Pairing
}

//ProveKey zk-SNARKs algorithm prove key
type ProveKey interface {
	Prove(cs R1CS, witness []FieldElement, mpc MPC) ([]byte, error)
	GetSnark() string
	GetPairing() string
	GetVKTag() string
	Marshaller
}

//VerifyProofKey vk
type VerifyProofKey interface {
	Verify(in []byte, limit string, mpc MPC) error
	GetSnark() string
	GetPairing() string
	Marshaller
}

// MPC mpc
type MPC interface {
	New(curve string, power uint) []byte
	Contribute(entropy, name string) error
	Verify() (bool, error)
	Beacon(string, int) error
	GetPower() int
	GetG1() []Point
	GetG2() []Point
	GetPairing() string
	GetHash() string
	VerifyWithHistory(srsBefore MPC) (bool, error)
	Marshaller
}

//Snarks zk-SNARKS
type Snarks interface {
	Name() string
	Setup(r1cs R1CS) (ProveKey, VerifyProofKey, error)
	GenCode(p, v []byte, circuitID [32]byte, t ChainType) []byte
	UnmarshalVK(in []byte) (VerifyProofKey, error)
	UnmarshalPK(in []byte) (ProveKey, error)
}

//VCMetrics metrics for prove and verify
type VCMetrics interface {
	UpdateGetDataTime(s, e int64)
	UpdateWaitTime(s, e int64)
	UpdateProveTime(s, e int64)
	UpdateVerifyTime(s, e int64)
	UpdateComputerTime(s, e int64)
	UpdateG1TPS(s, e int64, n int)
	UpdateG2TPS(s, e int64, n int)
}
