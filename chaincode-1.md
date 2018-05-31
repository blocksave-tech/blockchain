###系统链码
fabric-peer-node start.go
	// Create a self-signed CA for chaincode service
	ca, err := accesscontrol.NewCA() 自签名的公私秘钥证书
	if err != nil {
		logger.Panic("Failed creating authentication layer:", err)
	}
    
    createChaincodeServer
    默认设计chiancode链接地址：address: 0.0.0.0:7051　－－－》　0.0.0.0:7052
    chaincodeListenAddrKey = "peer.chaincodeListenAddress" = 0.0.0.0:7052
    
    创建createChaincodeServer　chaincode　ＣＣ 监听服务　地址为"peer.chaincodeListenAddress" = 0.0.0.0:7052
    
    ccSrv, ccEndpoint, err := createChaincodeServer(ca, peerHost)　
    ccSrv 为chaincode的ｇrpc服务　　默认无tls加密的
    ccEndpoint　0.0.0.0地址
    
    
    registerChaincodeSupport
    userRunsCC := chaincode.IsDevMode()　判断是否是以dev模式运行　是则ｔｒｕｅ
    
    pnid := viper.GetString("peer.networkId")　＝　ｄｅｖ
	pid := viper.GetString("peer.id")
    默认值：
    id: jdoe
    networkId: dev
    
    ChaincodeSupport支持ｃｈａｉｎｃｏｄｅ实例服务
    	theChaincodeSupport = &ChaincodeSupport{
		ca: ca,
		runningChaincodes: &runningChaincodes{
			chaincodeMap:  make(map[string]*chaincodeRTEnv),
			launchStarted: make(map[string]bool),
		}, peerNetworkID: pnid, peerID: pid,
	}
    
    theChaincodeSupport.auth = accesscontrol.NewAuthenticator(theChaincodeSupport, ca)
    theChaincodeSupport.peerAddress ＝0.0.0.0
    theChaincodeSupport.userRunsCC = true
    theChaincodeSupport.ccStartupTimeout =  300s
    theChaincodeSupport.peerTLS = true
    if !theChaincodeSupport.peerTLS {
		theChaincodeSupport.auth.DisableAccessCheck() 设计theChaincodeSupport.auth.bypass
	}
	theChaincodeSupport.keepalive = 0
    theChaincodeSupport.executetimeout = 30
    theChaincodeSupport.chaincodeLogLevel = info
    theChaincodeSupport.shimLogLevel = warning
    theChaincodeSupport.logFormat = format: '%{color}%{time:2006-01-02 15:04:05.000 MST} [%{module}] %{shortfunc} -> %{level:.4s} %{id:03x}%{color:reset} %{message}'
    解析：
    theChaincodeSupport.auth = accesscontrol.NewAuthenticator(theChaincodeSupport, ca)
    theChaincodeSupport.auth　＝　type authenticator struct {
	bypass bool
	mapper *certMapper
	pb.ChaincodeSupportServer
}
    bypass = true
    mapper = newClientCertKeyPair 函数指针，返回certKeyPair　ｃａ签名的公钥和对应的私钥
    pb.ChaincodeSupportServer　＝　 newInterceptor(srv, auth.authenticate)
   func newInterceptor(srv pb.ChaincodeSupportServer, auth authorization) pb.ChaincodeSupportServer {
	return &interceptor{
		next: srv,　＝　theChaincodeSupport
		auth: auth,　＝　函数auth.authenticate　＝　func (ac *authenticator) authenticate(msg *pb.ChaincodeMessage, stream grpc.ServerStream)
	}
}
其中pb.ChaincodeSupportServer有对应的函数Register

type ChaincodeSupportServer interface {
	Register(ChaincodeSupport_RegisterServer) error
}
type ChaincodeSupport_RegisterServer interface {
	Send(*ChaincodeMessage) error
	Recv() (*ChaincodeMessage, error)
	grpc.ServerStream
}



    
    
    
    
    
    
    
    