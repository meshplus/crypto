package crypto

//MethodName plugin function name
const MethodName = "NewSDK"

//Logger interface
type Logger interface {
	Debug(v ...interface{})
	Debugf(format string, v ...interface{})
	Info(v ...interface{})
	Infof(format string, v ...interface{})
	Notice(v ...interface{})
	Noticef(format string, v ...interface{})
	Warning(v ...interface{})
	Warningf(format string, v ...interface{})
	Error(v ...interface{})
	Errorf(format string, v ...interface{})
	Critical(v ...interface{})
	Criticalf(format string, v ...interface{})
}

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
	TaskID    string    `json:"taskID"`
	ChannelID string    `json:"channelID"`
	CircuitID [32]byte  `json:"circuitID"`
	Type      EventType `json:"type"`
	Event     []byte    `json:"event"` //json content
	TxHash    string    `json:"txHash"`
	BlockNum  int       `json:"blockNum"`
}

//EventCompute event compute
type EventCompute struct {
	CCName                 string `json:"ccName"`
	WebHook                string `json:"webHook"`
	WebHookBodyPattern     string `json:"webHookBodyPattern"`
	BusinessContractAddr   string `json:"businessContractAddr"`
	BusinessContractMethod string `json:"businessContractMethod"`
	Input                  string `json:"input"`
}

//EventFinish event finish
type EventFinish struct {
	Proof       string `json:"proof"`
	Result      string `json:"result"`
	Error       string `json:"error"`
	Response    []byte `json:"response"`
	NextCompute []byte `json:"nextCompute"`
}
