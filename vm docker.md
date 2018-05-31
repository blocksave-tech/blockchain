vm docker
fabric - core - container 处理docker的创建 启动关闭

chaincode 安装的镜像:
root@8631549a0816:/usr/local/bin# ls
chaincode  二进制文件


root@8631549a0816:/usr/local/bin# env
HOSTNAME=8631549a0816
LS_COLORS=
CORE_CHAINCODE_ID_NAME=mycc:1.0   名称
CORE_CHAINCODE_LOGGING_LEVEL=info  日志等级
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/usr/local/bin
CORE_PEER_TLS_ENABLED=false  是否启用加密通信
CORE_CHAINCODE_BUILDLEVEL=1.1.1-snapshot-849e304
CORE_CHAINCODE_LOGGING_FORMAT=%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}
SHLVL=1
HOME=/root
CORE_CHAINCODE_LOGGING_SHIM=warning   等级
_=/usr/bin/env
OLDPWD=/

______________________________________________-
<-chan int  像这样的只能接收值
chan<- int  像这样的只能发送值

type inProcStream struct {
	recv <-chan *pb.ChaincodeMessage 接受ChaincodeMessage类型的channel
	send chan<- *pb.ChaincodeMessage 发送ChaincodeMessage
}

func newInProcStream(recv <-chan *pb.ChaincodeMessage, send chan<- *pb.ChaincodeMessage) *inProcStream {
	return &inProcStream{recv, send}
}

fabric fsm状态机:  搞懂状态机的跳转状态
./core/chaincode/handler.go:412:        v.FSM = fsm.NewFSM(
./core/chaincode/shim/handler.go:180:   v.FSM = fsm.NewFSM(


fsm.Events事件:事件名 - 当前状态 --跳转到下一个状态
fsm.Callbacks:
before_事件名:进入事件前执行回调函数
enter_"状态":进入状态前的回调函数
enter_state: 状态跳变不一致的话 则执行的会 回调函数
after_事件名:事件后前执行回调函数




















































