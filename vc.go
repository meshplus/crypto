package crypto

//MethodName plugin function name
const MethodName = "NewSDK"

//NewSDKFunc plugin function type
type NewSDKFunc func(path, user, namespace string) (ChainSDK, error)

//EventType type EventType
type EventType int

//Event event
type Event struct {
	Type     EventType
	Event    []byte //json
	TxHash   []byte
	BlockNum int
}

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
	InvokeFinish(namespace string, nodes []string, address []byte, taskID []byte, proof, result string) ([]byte, error)
	//RegisterListening 注册监听EVENT_FINISH和EVENT_COMPUTE事件
	RegisterListening(namespace string, proxyAddress, businessAddress []byte) (chan *Event, error)
	//UnregisterListening 解注册事件
	UnregisterListening(namespace string, proxyAddress, businessAddress []byte) error
}

//EventCompute event compute
type EventCompute struct {
	TaskID                 string   `json:"taskID"`
	WebHook                string   `json:"webHook"`
	WebHookBodyPattern     string   `json:"webHookBodyPattern"`
	BusinessContractAddr   string   `json:"businessContractAddr"`
	BusinessContractMethod string   `json:"businessContractMethod"`
	Input                  string   `json:"input"`
	CircuitID              [32]byte `json:"circuitID"`
}

//EventFinish event finish
type EventFinish struct {
	TaskID   string `json:"taskID"`
	Proof    string `json:"proof"`
	Result   string `json:"result"`
	Response []byte `json:"response"`
}
