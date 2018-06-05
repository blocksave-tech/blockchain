peer - node - serve() 启动createChaincodeServer函数:
默认返回GRPC 服务对象ccSrv, Listen 的ccEndpoint地址 (本地接口地址:7052)
|
registerChaincodeSupport(ccSrv, ccEndpoint, ca)
-> NewChaincodeSupport(ccEndpoint, userRunsCC, ccStartupTimeout, ca)
    返回返回一个ChaincodeSupport对象
    type ChaincodeSupport struct {
        ca                accesscontrol.CA
        auth              accesscontrol.Authenticator
        runningChaincodes *runningChaincodes
        peerAddress       string
        ccStartupTimeout  time.Duration
        peerNetworkID     string
        peerID            string
        keepalive         time.Duration
        chaincodeLogLevel string
        shimLogLevel      string
        logFormat         string
        executetimeout    time.Duration
        userRunsCC        bool
        peerTLS           bool
    }
ChaincodeSupport.ca 调用NewCA - newCertKeyPair函数生成一对ca性质的私钥和公钥对应的证书
theChaincodeSupport.auth = accesscontrol.NewAuthenticator(theChaincodeSupport, ca)
```
func NewAuthenticator(srv pb.ChaincodeSupportServer, ca CA) Authenticator {
	auth := &authenticator{
		mapper: newCertMapper(ca.newClientCertKeyPair),
        //返回一个对之前对ca 私钥对后续产生的私钥 证书签名的管理函数
	}
	auth.ChaincodeSupportServer = newInterceptor(srv, auth.authenticate)
    /*返回一个ChaincodeSupportServer对象
    interceptor{
		next: srv,  //srv 等于ChaincodeSupport
		auth: auth,// 等于函数auth.authenticate, 验证是否是ca签名的客户端发送过来的注册消息,
        //因为theChaincodeSupport.peerTLS为false,所以函数默认直接退出
	}这个对象强转为ChaincodeSupportServer
    */
	return auth
}
```

theChaincodeSupport.runningChaincodes = &runningChaincodes{
			chaincodeMap:  make(map[string]*chaincodeRTEnv),
			launchStarted: make(map[string]bool),
		}初始化\申请内容空间
theChaincodeSupport.peerNetworkID = dev
theChaincodeSupport.peerID = jdoe
theChaincodeSupport.peerAddress = 本地接口地址:7052
theChaincodeSupport.userRunsCC = chaincode.IsDevMode()的返回值 如果配置文件chaincode.mode 为dev则true,否则false
theChaincodeSupport.ccStartupTimeout = 配置文件获取默认值startuptimeout: 300s 启动一个容器默认等待的时间
theChaincodeSupport.peerTLS = 获取peer.tls.enabled 默认为false
theChaincodeSupport.keepalive = chaincode.keepalive  <= 0 turns keepalive off chaincode和peer保存keepalive信号发送
theChaincodeSupport.executetimeout = chaincode.executetimeout 配置 执行invoke init的默认超时时间 在初始生产环境build iamge需要增加相应的时间,否则超市,设置超市防止失控的逻辑出现;
theChaincodeSupport.chaincodeLogLevel = chaincodde logging level 配置的日志等级参数
theChaincodeSupport.shimLogLevel = chaincodde logging shim 配置的日志等级参数
theChaincodeSupport.logFormat = chaincodde logging format 配置的日志等级参数


查看protoc-peer-chiancode_shim.proto文件直接一个函数 rpc接口函数
```
// Interface that provides support to chaincode execution. ChaincodeContext
// provides the context necessary for the server to respond appropriately.
service ChaincodeSupport {
    rpc Register(stream ChaincodeMessage) returns (stream ChaincodeMessage) {}
}
```
|
系统链码注册:
scc.RegisterSysCCs()
typeRegistry[path] = &inprocContainer{chaincode: cc}
path为系统链码的路径
cc为系统链码实现的chaincode对象实例(实现了invoke \init 方法)
typeRegistry全局对象:make(map[string]*inprocContainer)

inprocContainer对象:
type inprocContainer struct {
	chaincode shim.Chaincode  注册只实例化一个chaincode对象
	running   bool
	args      []string
	env       []string
	stopChan  chan struct{}
}

启动链的启动函数:(inprocContainer对象仅仅有一个launchInProc函数)
func (ipc *inprocContainer) launchInProc(ctxt context.Context, id string, args []string, env []string, ccSupport ccintf.CCSupport) error

在peer- node - serve() - 调用函数initSysCCs()
```
// Interface that provides support to chaincode execution. ChaincodeContext
// provides the context necessary for the server to respond appropriately.
service ChaincodeSupport {
    rpc Register(stream ChaincodeMessage) returns (stream ChaincodeMessage) {}
}
```
|
系统链码注册:
scc.RegisterSysCCs()
typeRegistry[path] = &inprocContainer{chaincode: cc}
path为系统链码的路径
cc为系统链码实现的chaincode对象实例(实现了invoke \init 方法)
typeRegistry全局对象:make(map[string]*inprocContainer)

inprocContainer对象:
type inprocContainer struct {
	chaincode shim.Chaincode  注册只实例化一个chaincode对象
	running   bool
	args      []string
	env       []string
	stopChan  chan struct{}
}

启动链的启动函数:(inprocContainer对象仅仅有一个launchInProc函数)
func (ipc *inprocContainer) launchInProc(ctxt context.Context, id string, args []string, env []string, ccSupport ccintf.CCSupport) error


func (vm *InprocVM) Start -- 调用 launchInProc函数
初始化系统链码:
在peer- node - serve() - 调用函数initSysCCs()

系统链部署:initSysCC -- DeploySysCCs -- deploySysCC部署系统链,并初始化;
所有系统链调用deploySysCC函数启动\初始化的:

其中:ccprov := ccprovider.GetChaincodeProvider() 返回链码启动实例: 返回ChaincodeProvider interface对象,齐总定义接口有:

```
type ChaincodeProvider interface {
	// GetContext returns a ledger context and a tx simulator; it's the
	// caller's responsability to release the simulator by calling its
	// done method once it is no longer useful
	GetContext(ledger ledger.PeerLedger, txid string) (context.Context, ledger.TxSimulator, error)
	// GetCCContext returns an opaque chaincode context
	GetCCContext(cid, name, version, txid string, syscc bool, signedProp *pb.SignedProposal, prop *pb.Proposal) interface{}
	// ExecuteChaincode executes the chaincode given context and args
	ExecuteChaincode(ctxt context.Context, cccid interface{}, args [][]byte) (*pb.Response, *pb.ChaincodeEvent, error)
	// Execute executes the chaincode given context and spec (invocation or deploy)
	Execute(ctxt context.Context, cccid interface{}, spec interface{}) (*pb.Response, *pb.ChaincodeEvent, error)
	// ExecuteWithErrorFilter executes the chaincode given context and spec and returns payload
	ExecuteWithErrorFilter(ctxt context.Context, cccid interface{}, spec interface{}) ([]byte, *pb.ChaincodeEvent, error)
	// Stop stops the chaincode given context and deployment spec
	Stop(ctxt context.Context, cccid interface{}, spec *pb.ChaincodeDeploymentSpec) error
}

```
以上接口实现在:
fabric - core - chaincode - ccproviderimpl.go文件实现的
type ccProviderContextImpl struct {
	ctx *ccprovider.CCContext
}

struct实现了对应的所有的方法

1: GetContext函数
txsim, err := ledger.NewTxSimulator(txid) 没有明白
ctxt := context.WithValue(context.Background(), TXSimulatorKey, txsim)
其中TXSimulatorKey key = "txsimulatorkey"
最终返回返回:ctxt txsim


2:GetCCContext函数
cccid := &CCContext{cid, name, version, txid, syscc, signedProp, prop, canName, nil}
其中canName := name + ":" + version
返回: ccProviderContextImpl{ctx: ctx} 其中ctx就是上面的cccid对象


3:ExecuteChaincode函数
func (c *ccProviderImpl) ExecuteChaincode(ctxt context.Context, cccid interface{}, args [][]byte) (*pb.Response, *pb.ChaincodeEvent, error) {
	return ExecuteChaincode(ctxt, cccid.(*ccProviderContextImpl).ctx, args)
}

4: Execute 函数
func (c *ccProviderImpl) Execute(ctxt context.Context, cccid interface{}, spec interface{}) (*pb.Response, *pb.ChaincodeEvent, error) {
	return Execute(ctxt, cccid.(*ccProviderContextImpl).ctx, spec)
}

5: ExecuteWithErrorFilter函数
func (c *ccProviderImpl) ExecuteWithErrorFilter(ctxt context.Context, cccid interface{}, spec interface{}) ([]byte, *pb.ChaincodeEvent, error) {
	return ExecuteWithErrorFilter(ctxt, cccid.(*ccProviderContextImpl).ctx, spec)
}

6: Stop函数
func (c *ccProviderImpl) Stop(ctxt context.Context, cccid interface{}, spec *pb.ChaincodeDeploymentSpec) error {
	if theChaincodeSupport != nil {
		return theChaincodeSupport.Stop(ctxt, cccid.(*ccProviderContextImpl).ctx, spec)
	}
	panic("ChaincodeSupport not initialized")
}

启动 初始化系统链码:
deploySysCC -- 调用 ccprov.ExecuteWithErrorFilter(ctxt, cccid, chaincodeDeploymentSpec)

1>
ctxt: ctxt := context.Background() 返回对象
2>
cccid:ccprov.GetCCContext(chainID, chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeId.Name, version, txid, true, nil, nil)
    version := util.GetSysCCVersion()
    txid := util.GenerateUUID()
3>
chaincodeDeploymentSpec:
ChaincodeDeploymentSpec{ExecEnv: pb.ChaincodeDeploymentSpec_SYSTEM, ChaincodeSpec: spec, CodePackage: codePackageBytes}

    其中
    ExecEnv: 等于ChaincodeDeploymentSpec_SYSTEM
    ChaincodeSpec 等于:
        ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: chaincodeID, Input: &pb.ChaincodeInput{Args: syscc.InitArgs}}
        其中chaincodeID 等于chaincodeID := &pb.ChaincodeID{Path: syscc.Path, Name: syscc.Name}
    CodePackage: 等于codePackageBytes []byte 空对象


系统链码启动 初始化 ---- 执行函数ExecuteWithErrorFilter:
func ExecuteWithErrorFilter(ctxt context.Context, cccid *ccprovider.CCContext, spec interface{}) ([]byte, *pb.ChaincodeEvent, error) {
	res, event, err := Execute(ctxt, cccid, spec)
	if err != nil {
		chaincodeLogger.Errorf("ExecuteWithErrorFilter %s error: %+v", cccid.Name, err)
		return nil, nil, err
	}
	if res == nil {
		chaincodeLogger.Errorf("ExecuteWithErrorFilter %s get nil response without error", cccid.Name)
		return nil, nil, err
	}
	if res.Status != shim.OK {
		return nil, nil, errors.New(res.Message)
	}
	return res.Payload, event, nil
}

Execute --->　Launch　函数
cds, _ = spec.(*pb.ChaincodeDeploymentSpec)　等于ChaincodeDeploymentSpec{ExecEnv: pb.ChaincodeDeploymentSpec_SYSTEM, ChaincodeSpec: spec, CodePackage: codePackageBytes}
cID = cds.ChaincodeSpec.ChaincodeId　等于chaincodeID := &pb.ChaincodeID{Path: syscc.Path, Name: syscc.Name}
cMsg = cds.ChaincodeSpec.Input　　系统链码的初始化参数　&pb.ChaincodeInput{Args: syscc.InitArgs}

满足条件：
if (!chaincodeSupport.userRunsCC || cds.ExecEnv == pb.ChaincodeDeploymentSpec_SYSTEM) && (chrte == nil || chrte.handler == nil) {
因：chaincodeSupport.userRunsCC　不等于ｄｅｖ　所以为ｆａｌｓｅ;  cds.ExecEnv = pb.ChaincodeDeploymentSpec_SYSTEM  之前没有注册过，所以　chrte＝nil

 －－－＞　chaincodeSupport.launchAndWaitForRegister(context, cccid, cds, &ccLauncherImpl{context, chaincodeSupport, cccid, cds, builder})

其中ccLauncherImpl对象：
type ccLauncherImpl struct {
	ctxt      context.Context
	ccSupport *ChaincodeSupport　＝　theChaincodeSupport 全局的
	cccid     *ccprovider.CCContext　　每个链码参数不同
	cds       *pb.ChaincodeDeploymentSpec　每个链码参数不同
	builder   api.BuildSpecFactory
}


１＞
cccid：　cccid:ccprov.GetCCContext(chainID, chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeId.Name, version, txid, true, nil, nil)
    version := util.GetSysCCVersion()
    txid := util.GenerateUUID()

２＞
cds等于chaincodeDeploymentSpec:
ChaincodeDeploymentSpec{ExecEnv: pb.ChaincodeDeploymentSpec_SYSTEM, ChaincodeSpec: spec, CodePackage: codePackageBytes}

    其中
    ExecEnv: 等于ChaincodeDeploymentSpec_SYSTEM
    ChaincodeSpec 等于:
        ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: chaincodeID, Input: &pb.ChaincodeInput{Args: syscc.InitArgs}}
        其中chaincodeID 等于chaincodeID := &pb.ChaincodeID{Path: syscc.Path, Name: syscc.Name}
    CodePackage: 等于codePackageBytes []byte 空对象

＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿


ccLauncherImpl对象调用launch函数：
```
func (ccl *ccLauncherImpl) launch(ctxt context.Context, notfy chan bool) (interface{}, error) {
	//launch the chaincode
	args, env, filesToUpload, err := ccl.ccSupport.getLaunchConfigs(ccl.cccid, ccl.cds.ChaincodeSpec.Type)
	if err != nil {
		return nil, err
	}

	canName := ccl.cccid.GetCanonicalName()

	chaincodeLogger.Debugf("start container: %s(networkid:%s,peerid:%s)", canName, ccl.ccSupport.peerNetworkID, ccl.ccSupport.peerID)
	chaincodeLogger.Debugf("start container with args: %s", strings.Join(args, " "))
	chaincodeLogger.Debugf("start container with env:\n\t%s", strings.Join(env, "\n\t"))

	//set up the shadow handler JIT before container launch to
	//reduce window of when an external chaincode can sneak in
	//and use the launching context and make it its own
	preLaunchFunc := func() error {
		ccl.ccSupport.preLaunchSetup(canName, notfy)
		return nil
	}

	ccid := ccintf.CCID{ChaincodeSpec: ccl.cds.ChaincodeSpec, NetworkID: ccl.ccSupport.peerNetworkID, PeerID: ccl.ccSupport.peerID, Version: ccl.cccid.Version}
	sir := container.StartImageReq{CCID: ccid, Builder: ccl.builder, Args: args, Env: env, FilesToUpload: filesToUpload, PrelaunchFunc: preLaunchFunc}
	ipcCtxt := context.WithValue(ctxt, ccintf.GetCCHandlerKey(), ccl.ccSupport)

	vmtype, _ := ccl.ccSupport.getVMType(ccl.cds)
	resp, err := container.VMCProcess(ipcCtxt, vmtype, sir)

	return resp, err
}

```

１＞
args, env, filesToUpload, err := ccl.ccSupport.getLaunchConfigs(ccl.cccid, ccl.cds.ChaincodeSpec.Type)
返回值：
args："chaincode　-peer.address=本地接口地址:7052" 其中chaincode是可运行程序
envs：
    CORE_CHAINCODE_ID_NAME＝canName　等于name + ":" + version　例如lscc+1.1.0
    CORE_PEER_TLS_ENABLED=false
    CORE_CHAINCODE_LOGGING_LEVEL=　根据theChaincodeSupport成员对象赋值此对象
    CORE_CHAINCODE_LOGGING_SHIM=　根据theChaincodeSupport成员对象赋值此对象
    CORE_CHAINCODE_LOGGING_FORMAT=　根据theChaincodeSupport成员对象赋值此对象


2>
preLaunchFunc := func() error {
		ccl.ccSupport.preLaunchSetup(canName, notfy)
		return nil
	}
   preLaunchSetup里面执行：chaincodeSupport.runningChaincodes.chaincodeMap[chaincode] = &chaincodeRTEnv{handler: &Handler{readyNotify: notfy}}
chaincodeSupport等于theChaincodeSupport

theChaincodeSupport　－　runningChaincodes　：
type runningChaincodes struct {
	sync.RWMutex
	// chaincode environment for each chaincode
	chaincodeMap map[string]*chaincodeRTEnv

	//mark the starting of launch of a chaincode so multiple requests
	//do not attempt to start the chaincode at the same time
	launchStarted map[string]bool
}
对chaincodeMap map[string]*chaincodeRTEnv赋值
type Handler struct {
	sync.RWMutex
	//peer to shim grpc serializer. User only in serialSend
	serialLock  sync.Mutex
	ChatStream  ccintf.ChaincodeStream
	FSM         *fsm.FSM
	ChaincodeID *pb.ChaincodeID
	ccInstance  *sysccprovider.ChaincodeInstance

	chaincodeSupport *ChaincodeSupport
	registered       bool
	readyNotify      chan bool   －－－－－－－－－－－－－复制上层的notfy := make(chan bool, 1)对象
	// Map of tx txid to either invoke tx. Each tx will be
	// added prior to execute and remove when done execute
	txCtxs map[string]*transactionContext

	txidMap map[string]bool

	// used to do Send after making sure the state transition is complete
	nextState chan *nextStateInfo
}

３＞
ccid := ccintf.CCID{ChaincodeSpec: ccl.cds.ChaincodeSpec, NetworkID: ccl.ccSupport.peerNetworkID, PeerID: ccl.ccSupport.peerID, Version: ccl.cccid.Version}
 ccl.cds.ChaincodeSpec其中：
 ChaincodeSpec 等于:
        ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: chaincodeID, Input: &pb.ChaincodeInput{Args: syscc.InitArgs}}
        其中chaincodeID 等于chaincodeID := &pb.ChaincodeID{Path: syscc.Path, Name: syscc.Name}
    CodePackage: 等于codePackageBytes []byte 空对象
ccl.ccSupport.peerNetworkID：　等于theChaincodeSupport.peerNetworkID = dev
ccl.ccSupport.peerID: 等于ｊｏｂｅ
ccl.cccid.Version：　等于version := util.GetSysCCVersion()

４＞　StartImageReq　启动请求对象
sir := container.StartImageReq{CCID: ccid, Builder: ccl.builder, Args: args, Env: env, FilesToUpload: filesToUpload, PrelaunchFunc: preLaunchFunc}
ccid等于上面分析的ccid
ccl.builder　函数　应该没有调用
FilesToUpload　应该等于ｎｉｌ
PrelaunchFunc　等于　２＞指示的通知回调函数


５＞
ipcCtxt := context.WithValue(ctxt, ccintf.GetCCHandlerKey(), ccl.ccSupport)
构造：
Context对象　父Context指向ctxt　　ｋｅｙ等于GetCCHandlerKey（）＝　＂CCHANDLER＂　　ｖａｌｕｅ等于theChaincodeSupport对象


６＞
 getVMType(cds *pb.ChaincodeDeploymentSpec)
 系统链返回container.SYSTEM

７＞
resp, err := container.VMCProcess(ipcCtxt, vmtype, sir)
参数：
是上面解析的３个参数
```
func VMCProcess(ctxt context.Context, vmtype string, req VMCReqIntf) (interface{}, error) {
	v := vmcontroller.newVM(vmtype)
	//返回v = &inproccontroller.InprocVM{}对象
	if v == nil {
		return nil, fmt.Errorf("Unknown VM type %s", vmtype)
	}

	c := make(chan struct{})
	var resp interface{}
	go func() {
		defer close(c)

		id, err := v.GetVMName(req.getCCID(), nil)
        //其中req.getCCID()　返回就是　３＞　ccid对象
		if err != nil {
			resp = VMCResp{Err: err}
			return
		}
		vmcontroller.lockContainer(id)
		resp = req.do(ctxt, v)
		vmcontroller.unlockContainer(id)
	}()

	select {
	case <-c:
		return resp, nil
	case <-ctxt.Done():
		//TODO cancel req.do ... (needed) ?
		<-c
		return nil, ctxt.Err()
	}
}
```


８＞　StartImageReq　对象＋函数
//StartImageReq - properties for starting a container.
type StartImageReq struct {　　
　　　// 4 > 中构造的对象　赋值的
	ccintf.CCID　／／返回就是　３＞　ccid对象
	Builder       api.BuildSpecFactory
	Args          []string
	Env           []string
	FilesToUpload map[string][]byte
	PrelaunchFunc api.PrelaunchFunc
}

func (si StartImageReq) do(ctxt context.Context, v api.VM) VMCResp {
	var resp VMCResp

	if err := v.Start(ctxt, si.CCID, si.Args, si.Env, si.FilesToUpload, si.Builder, si.PrelaunchFunc); err != nil {
		resp = VMCResp{Err: err}
	} else {
		resp = VMCResp{}
	}

	return resp
}


StartImageReq对象只调用了v.Start函数：　－－－－实际调用　－－－－　inproccontroller.InprocVM{}　中的函数－－－＞
func (vm *InprocVM) Start(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, filesToUpload map[string][]byte, builder container.BuildSpecFactory, prelaunchFunc container.PrelaunchFunc)

９＞　func (vm *InprocVM) Start　函数
ipctemplate := typeRegistry[path] 返回对应链码的chaincode实例（有ｉｎｖｏｋｅ init函数）
instName, _ := vm.GetVMName(ccid, nil)　返回系统链码名＋ｖｅｒｓｉｏｎ　例如　cscc+util.GetSysCCVersion()

１０＞　instRegistry       = make(map[string]*inprocContainer)　标示已经实例化后的对象
ipc, err := vm.getInstance(ctxt, ipctemplate, instName, args, env)
实际做了：
instRegistry[instName] = &inprocContainer{args: args, env: env, chaincode: ipctemplate.chaincode, stopChan: make(chan struct{})}
其中ipctemplate.chaincode就是实例化后的chaincode实例对象
args　传递的参数

１１＞
ccSupport, ok := ctxt.Value(ccintf.GetCCHandlerKey()).(ccintf.CCSupport)　直接从ｓｔａｒｔ函数的ctxt参数中获取theChaincodeSupport对象

if prelaunchFunc != nil {
		if err = prelaunchFunc(); err != nil {
			return err
		}
	}

ipc.running = true　标识已经实例化完成


１２＞ 系统链码启动函数
go func() {
	ipc.launchInProc(ctxt, instName, args, env, ccSupport)
}


１３＞
himStartInProc(env, args, ipc.chaincode, ccRcvPeerSend, peerRcvCCSend)　实际调用：
err := chatWithPeer(chaincodename, stream, cc)　
参数是
chaincodename　系统链码名+verseion
stream  stream := newInProcStream(recv, send) chain输入　输出ｃｈａｉｎ对象
cc：　是chaincode　实例对象含有　ｉｎｖｏｋｅ　ｉｎｉｔ方法

chatWithPeer　－－－　调用　handler := newChaincodeHandler(stream, cc)　构造系统链码状态机



１４＞
inprocStream := newInProcStream(peerRcvCCSend, ccRcvPeerSend)　函数
err := ccSupport.HandleChaincodeStream(ctxt, inprocStream)
ccSupport实际就是全局theChaincodeSupport对象

func (chaincodeSupport *ChaincodeSupport) HandleChaincodeStream(ctxt context.Context, stream ccintf.ChaincodeStream) error {
	return HandleChaincodeStream(chaincodeSupport, ctxt, stream)
}

func HandleChaincodeStream(chaincodeSupport *ChaincodeSupport, ctxt context.Context, stream ccintf.ChaincodeStream) error {
	deadline, ok := ctxt.Deadline()
	chaincodeLogger.Debugf("Current context deadline = %s, ok = %v", deadline, ok)
	handler := newChaincodeSupportHandler(chaincodeSupport, stream)　启用ｐｅｅｒ节点的状态机
	return handler.processStream()　peer节点状态机的信息处理函数
}

++++++++++++++++++++++++++++++++++++++++

系统链码　和ｐｅｅｒ交互的入口函数：
func (ipc *inprocContainer) launchInProc(ctxt context.Context, id string, args []string, env []string, ccSupport ccintf.CCSupport) error
１＞

err := shimStartInProc(env, args, ipc.chaincode, ccRcvPeerSend, peerRcvCCSend)
＜１＞　shimStartInProc    = shim.StartInProc
＜２＞　调用　err := chatWithPeer(chaincodename, stream, cc)

２＞
err := ccSupport.HandleChaincodeStream(ctxt, inprocStream)

调用：
func HandleChaincodeStream(chaincodeSupport *ChaincodeSupport, ctxt context.Context, stream ccintf.ChaincodeStream) error {
	deadline, ok := ctxt.Deadline()
	chaincodeLogger.Debugf("Current context deadline = %s, ok = %v", deadline, ok)
	handler := newChaincodeSupportHandler(chaincodeSupport, stream)
	return handler.processStream()
}
＜１＞　newChaincodeSupportHandler
＜２＞　processStream


之间的交互流程：
cc:
发送：ChaincodeMessage{Type: pb.ChaincodeMessage_REGISTER, Payload: payload}　其中payload, err := proto.Marshal(pb.ChaincodeID{Name: chaincodename})
其中chaincodename就是：　系统链码名＋版本

peer:
接受：ChaincodeMessage_REGISTER消息
1>
before_ChaincodeMessage_REGISTER消息之前调用回调函数：beforeRegisterEvent
    beforeRegisterEvent：
    内部调用：　err = handler.chaincodeSupport.registerHandler(handler)
    key := chaincodehandler.ChaincodeID.Name　获取系统链码＋version
    chrte2, ok := chaincodeSupport.chaincodeHasBeenLaunched(key)　
    if ok && chrte2.handler.registered == true {
            chaincodeLogger.Debugf("duplicate registered handler(key:%s) return error", key)
            // Duplicate, return error
            return newDuplicateChaincodeHandlerError(chaincodehandler)
        }
    判断是已经注册过了，因为之前已经注册，但是chrte2.handler.registered　等于false　所以还没有完成注册完成
    所以会执行：
    if chrte2 != nil {
            chaincodehandler.readyNotify = chrte2.handler.readyNotify
            chrte2.handler = chaincodehandler
        }
    chaincodehandler.registered = true
        chaincodehandler.txCtxs = make(map[string]*transactionContext)
        chaincodehandler.txidMap = make(map[string]bool)


    根据系统链码名：版本　解析出系统链码名　　版本　路径　　－－　复制到handler.ccInstance类型中
    handler.decomposeRegisteredName(handler.ChaincodeID)

    发送消息到cc
    ChaincodeMessage{Type: pb.ChaincodeMessage_REGISTERED}

2>"enter_" + establishedstate 进入此状态　调用函数enterEstablishedState
handler.readyNotify <- true 通知ｐｅｅｒ上层　已经初始完了

cc:
接受消息ChaincodeMessage_REGISTERED
初始created　事件ChaincodeMessage_REGISTERED　下一个状态established

事件之前回调"before_" + pb.ChaincodeMessage_REGISTERED.String()　－－－　beforeRegistered
函调函数：beforeRegistered　　只做了打印ｌｏｇ：　chaincodeLogger.Debugf("Received %s, ready for invocations", pb.ChaincodeMessage_REGISTERED)
