package crypto

import (
	"bytes"
	"sync"
)

//MethodName plugin function name
const MethodName = "NewSDK"

//curve name
const (
	CurveNameBN254          = "bn254"
	CurveNameSM9            = "sm9"
	CurveNameCurve101       = "testCurve101"
	CurveNameCurve101NonFFT = "testCurve101NonFFT"
)

//NewSDKFunc plugin function type
type NewSDKFunc func(path, user, namespace string, logger Logger) (ChainSDK, error)

//EventType type EventType
type EventType int

//event type
const (
	EventTypeCompute EventType = iota
	EventTypeFinish
)

//ChainSDK sdk for specific blockchain
type ChainSDK interface {
	//ChainType 返回链的类型
	ChainType() string
	//InvokeFinish 调用Finish方法, namespace是分区（通道），address是合约地址（名称）
	InvokeFinish(nodes []string, address, taskID, proof, result, error string) ([]byte, error)
	//RegisterListening 注册监听EVENT_FINISH和EVENT_COMPUTE事件
	RegisterListening(proxyAddress, businessAddress []string) (chan *Event, error)
	//UnregisterListening 解注册事件
	UnregisterListening(address string) error
}

//Event event
type Event struct {
	ChannelID string    `json:"channelID"`
	Type      EventType `json:"type"`
	Event     []byte    `json:"event"` //json content
	TxHash    string    `json:"txHash"`
	BlockNum  int       `json:"blockNum"`
}

//EventCompute event compute
type EventCompute struct {
	TaskID                 string   `json:"taskID"`
	CircuitID              [32]byte `json:"circuitID"`
	CCName                 string   `json:"ccName"`
	WebHook                string   `json:"webHook"`
	WebHookBodyPattern     string   `json:"webHookBodyPattern"`
	BusinessContractAddr   string   `json:"businessContractAddr"`
	BusinessContractMethod string   `json:"businessContractMethod"`
	Input                  string   `json:"input"`
}

//EventFinish event finish
type EventFinish struct {
	TaskID      string   `json:"taskID"`
	CircuitID   [32]byte `json:"circuitID"`
	Proof       string   `json:"proof"`
	Result      string   `json:"result"`
	Error       string   `json:"error"`
	Response    []byte   `json:"response"`
	NextCompute []byte   `json:"nextCompute"`
}

//Response callback response
type Response struct {
	Continue bool `json:"continue"`
	//NextParam: proxyContractAddr, input, businessContractAddr, businessContractMethod, WebHook and WebHookBodyPattern
	NextParam [6]string `json:"nextParam"`
	//response
	Response []byte `json:"response"`
}

var pairing sync.Map

//RegisterPairing register pairing
func RegisterPairing(p Pairing) {
	pairing.Store(p.Name(), p)
}

//UnMarshalPairing unmarshal pairing
func UnMarshalPairing(data []byte) Pairing {
	var ret Pairing
	pairing.Range(func(key, value interface{}) bool {
		if bytes.Equal(data, []byte(key.(string))) {
			ret = value.(Pairing)
			return false
		}
		return true
	})

	return ret
}
