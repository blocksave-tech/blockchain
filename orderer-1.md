orderer  流程梳理：

func main() {
	server.Main()　入口函数
}

conf, err := config.Load()　加载orderer的配置文件　　读取配置文件orderer.yaml文件

Start(fullCmd, conf)　启动orderer服务

func Start(cmd string, conf *config.TopLevel) 　
函数解析：

signer := localmsp.NewSigner()　本地签名对象
serverConfig := initializeServerConfig(conf)　返回tls通信加密对象和Keepalive对象
grpcServer := initializeGrpcServer(conf, serverConfig)　构造grpc对象
tlsCallback　＝　updateTrustedRoots　更新信任跟　？？？？？





















代码分析技




newChainSupport对象