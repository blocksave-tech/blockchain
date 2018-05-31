###系统链码chaincode
#### 注册：
１、fabric-node-peer start.go
+196: registerChaincodeSupport(ccSrv, ccEndpoint, ca) --> scc.RegisterSysCCs()
保存全局变量：
typeRegistry        = make(map[string]*inprocContainer)　中

例如：
typeRegistry[path] = &inprocContainer{chaincode: cc}　保存的chaincode对象

type inprocContainer struct {
	chaincode shim.Chaincode　　保存的chaincode对象
	running   bool
	args      []string
	env       []string
	stopChan  chan struct{}
}

系统链初始化对象：
var systemChaincodes = []*SystemChaincode{
	{
		Enabled:           true,
		Name:              "cscc",
		Path:              "github.com/hyperledger/fabric/core/scc/cscc",　　保存的路径
		InitArgs:          [][]byte{[]byte("")},
		Chaincode:         &cscc.PeerConfiger{},　保存的chaincode对象　含有方法
		InvokableExternal: true, // cscc is invoked to join a channel
	},


#### 部署：

	//initialize system chaincodes 
    初始化系统链码：
＋276	initSysCCs()

func initSysCCs() {
	//deploy system chaincodes
	scc.DeploySysCCs("")
	logger.Infof("Deployed system chaincodes")
}

func DeploySysCCs(chainID string) {
	for _, sysCC := range systemChaincodes {
		deploySysCC(chainID, sysCC)
	}
}

——————————————————————————————————————————
定义全局系统链工厂接口sccProviderFactory
type sccProviderFactory struct {
}

工厂的实现类：
// ccProviderImpl is an implementation of the ccprovider.ChaincodeProvider interface
type sccProviderImpl struct {
}

sccFactory　＝　&sccProviderFactory{}


如果sccFactory调用　sccFactory.NewSystemChaincodeProvider()获取一个实现类对象： &sccProviderImpl{}

type sccProviderImpl struct {
}
有接口：
IsSysCC
IsSysCCAndNotInvokableCC2CC
GetQueryExecutorForLedger
IsSysCCAndNotInvokableExternal
GetApplicationConfig
PolicyManager
————————————————————————————————————————————————————————————————————————————————————


fabric-core-common-ccprovider-ccprovider.go  定义全局系统链工厂接口ChaincodeProvider
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

ChaincodeProvider的实现类在：
fabric-core-chaincode ccproviderimpl.go ccProviderFactory

type ccProviderFactory struct {
}

ccProviderFactory的实现类：
type ccProviderImpl struct {
}

调用：
ccFactory = &ccProviderFactory{}
func (c *ccProviderFactory) NewChaincodeProvider() ccprovider.ChaincodeProvider {
	return &ccProviderImpl{}
}


调用获取ccProviderImpl：　ccProviderImpl　＝　ccFactory.NewChaincodeProvider()

type ccProviderImpl struct {
}
含有的接口：
GetContext
GetCCContext
ExecuteChaincode
Execute
ExecuteWithErrorFilter
Stop


系统链初始化：
deploySysCC(chainID　＝　“” string, syscc *SystemChaincode)

参数：

获取ChaincodeDeploymentSpec参数值：

chaincodeID := &pb.ChaincodeID{Path: syscc.Path, Name: syscc.Name}
spec := &pb.ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: chaincodeID, Input: &pb.ChaincodeInput{Args: syscc.InitArgs}}

type ChaincodeDeploymentSpec struct {
	ChaincodeSpec *ChaincodeSpec `protobuf:"bytes,1,opt,name=chaincode_spec,json=chaincodeSpec" json:"chaincode_spec,omitempty"`
	// Controls when the chaincode becomes executable.
	EffectiveDate *google_protobuf1.Timestamp                  `protobuf:"bytes,2,opt,name=effective_date,json=effectiveDate" json:"effective_date,omitempty"`
	CodePackage   []byte                                       `protobuf:"bytes,3,opt,name=code_package,json=codePackage,proto3" json:"code_package,omitempty"`
	ExecEnv       ChaincodeDeploymentSpec_ExecutionEnvironment `protobuf:"varint,4,opt,name=exec_env,json=execEnv,enum=protos.ChaincodeDeploymentSpec_ExecutionEnvironment" json:"exec_env,omitempty"`
}

func buildSysCC(context context.Context, spec *pb.ChaincodeSpec) (*pb.ChaincodeDeploymentSpec, error) {
	var codePackageBytes []byte
	chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ExecEnv: pb.ChaincodeDeploymentSpec_SYSTEM, ChaincodeSpec: spec, CodePackage: codePackageBytes}
	return chaincodeDeploymentSpec, nil
}

获取CCContext　参数值：

cccid := ccprov.GetCCContext(chainID, chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeId.Name, version, txid, true, nil, nil)

// ccProviderContextImpl contains the state that is passed around to calls to methods of ccProviderImpl
type ccProviderContextImpl struct {
	ctx *ccprovider.CCContext
}

ctx := ccprovider.NewCCContext(cid, name, version, txid, syscc, signedProp, prop)
canName := name + ":" + version

cccid := &CCContext{cid, name, version, txid, syscc, signedProp, prop, canName, nil}


//CCContext pass this around instead of string of args
type CCContext struct {
	//ChainID chain id
	ChainID string　　＝　“”

	//Name chaincode name
	Name string　　系统链名

	//Version used to construct the chaincode image and register
	Version string　版本

	//TxID is the transaction id for the proposal (if any)
	TxID string　　　＝　version := util.GetSysCCVersion()　ＵＵＩＤ

	//Syscc is this a system chaincode
	Syscc bool　＝　ｔｒue

	//SignedProposal for this invoke (if any)
	//this is kept here for access control and in case we need to pass something
	//from this to the chaincode
	SignedProposal *pb.SignedProposal = nil

	//Proposal for this invoke (if any)
	//this is kept here just in case we need to pass something
	//from this to the chaincode
	Proposal *pb.Proposal = nil 

	//this is not set but computed (note that this is not exported. use GetCanonicalName)
	canonicalName string = 系统链名＋ｖｅｒｓｉｏｎ

	// this is additional data passed to the chaincode
	ProposalDecorations map[string][]byte = nil
}

执行：
_, _, err = ccprov.ExecuteWithErrorFilter(ctxt, cccid, chaincodeDeploymentSpec)

func ExecuteWithErrorFilter(ctxt context.Context, cccid *ccprovider.CCContext, spec interface{}) ([]byte, *pb.ChaincodeEvent, error) {
	res, event, err := Execute(ctxt, cccid, spec)　其中：　cccid＝　CCContext　spec＝　ChaincodeDeploymentSpec
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

Execute　--> theChaincodeSupport.Launch(ctxt, cccid, spec)

cID = cds.ChaincodeSpec.ChaincodeId 系统链名　版本　路径
cMsg = cds.ChaincodeSpec.Input　系统链init初始化参数

Execute执行系统链初始化：
cctyp := pb.ChaincodeMessage_INIT
cMsg 等于系统链初始化init参数
cMsg.Decorations　＝　nil
        
ccMsg, err = createCCMessage(cctyp, cccid.ChainID, cccid.TxID, cMsg)
haincodeMessage{Type: typ, Payload: payload, Txid: txid, ChannelId: cid}
Type := pb.ChaincodeMessage_INIT
payload　＝　等于系统链init参数
ChannelId　＝　”“


Launch函数处理:
Execute函数中调用： theChaincodeSupport.Launch(ctxt, cccid, spec)　函数：
cccid参数：
cccid := &CCContext{cid, name, version, txid, syscc, signedProp, prop, canName, nil}

参数值：
type CCContext struct {
	ChainID string　　＝　“”
	Name string　　系统链名
	Version string　版本

	//TxID is the transaction id for the proposal (if any)
	TxID string　　　＝　version := util.GetSysCCVersion()　ＵＵＩＤ
	Syscc bool　＝　ｔｒue
	SignedProposal *pb.SignedProposal = nil
	Proposal *pb.Proposal = nil 
	canonicalName string = 系统链名＋ｖｅｒｓｉｏｎ
	ProposalDecorations map[string][]byte = nil
}

spec参数：
cds, _ = spec.(*pb.ChaincodeDeploymentSpec)

chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ExecEnv: pb.ChaincodeDeploymentSpec_SYSTEM, ChaincodeSpec: spec, CodePackage: codePackageBytes}

codePackageBytes为空[]byte
spec 参数等于：

spec := &pb.ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: chaincodeID, Input: &pb.ChaincodeInput{Args: syscc.InitArgs}}

其中chaincodeID等于：
chaincodeID := &pb.ChaincodeID{Path: syscc.Path, Name: syscc.Name}

Launch　函数－－－＞chaincodeSupport.launchAndWaitForRegister(context, cccid, cds, &ccLauncherImpl{context, chaincodeSupport, cccid, cds, builder})

cds　：等于chaincodeDeploymentSpec
GenerateDockerBuild函数：　
_generateDockerfile　创建dockerfile
_generateDockerBuild 编译docker

函数：
err = chaincodeSupport.launchAndWaitForRegister(context, cccid, cds, &ccLauncherImpl{context, chaincodeSupport, cccid, cds, builder})

canName参数　系统链+version

chaincodeSupport.runningChaincodes.launchStarted[canName] = true 标志系统链码已经起来
for{} 程序退出，最后在删除：delete(chaincodeSupport.runningChaincodes.launchStarted, canName)
chaincodeSupport.userRunsCC　＝　true dev模式
cds.ExecEnv = pb.ChaincodeDeploymentSpec_SYSTEM

参数：&ccLauncherImpl{context, chaincodeSupport, cccid, cds, builder}
chaincodeSupport　参数等于系统全局theChaincodeSupport
cccid　等于：&CCContext{cid, name, version, txid, syscc, signedProp, prop, canName, nil}
cds　等于：等于chaincodeDeploymentSpec


launchAndWaitForRegister函数里面：
resp, err := launcher.launch(ctxt, notfy)
其中notfy := make(chan bool, 1)

其中launcher.launch(ctxt, notfy)函数就是：
ccLauncherImpl{context, chaincodeSupport, cccid, cds, builder}.launch(ctxt, notfy)

分析函数：
func (ccl *ccLauncherImpl) launch(ctxt context.Context, notfy chan bool) (interface{}, error) {

函数：
args, env, filesToUpload, err := ccl.ccSupport.getLaunchConfigs(ccl.cccid, ccl.cds.ChaincodeSpec.Type)
参数ccl.cccid等于&CCContext{cid, name, version, txid, syscc, signedProp, prop, canName, nil}
ccl.cds.ChaincodeSpec.Type　等于pb.ChaincodeSpec_Type_value["GOLANG"]

此函数返回参数：
args：chaincode　-peer.address = 0.0.0.0:7051
envs:CORE_CHAINCODE_ID_NAME="系统链＋version" + CORE_PEER_TLS_ENABLED=true／false + [CORE_TLS_CLIENT_KEY_PATH=] + CORE_CHAINCODE_LOGGING_LEVEL= info + CORE_CHAINCODE_LOGGING_SHIM= waing + CORE_CHAINCODE_LOGGING_FORMAT= "%sf" 
filesToUpload 等于nil

ccl.ccSupport.preLaunchSetup(canName, notfy)　函数：
chaincodeSupport.runningChaincodes.chaincodeMap[系统链＋版本] = &chaincodeRTEnv{handler: &Handler{readyNotify: notfy}}

结构体：
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
	readyNotify      chan bool　　其中应用层传递的channel 用来判断是否成功部署初始化，则成功则返回ｔｒｕｅ信息
	// Map of tx txid to either invoke tx. Each tx will be
	// added prior to execute and remove when done execute
	txCtxs map[string]*transactionContext

	txidMap map[string]bool

	// used to do Send after making sure the state transition is complete
	nextState chan *nextStateInfo
}

ccid＝ccintf.CCID{ChaincodeSpec: ccl.cds.ChaincodeSpec, NetworkID: ccl.ccSupport.peerNetworkID, PeerID: ccl.ccSupport.peerID, Version: ccl.cccid.Version}

其中 ccl.cds.ChaincodeSpec等于spec := &pb.ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: chaincodeID, Input: &pb.ChaincodeInput{Args: syscc.InitArgs}}

ccl.ccSupport.peerNetworkID　＝ dev
ccl.ccSupport.peerID = jdoe
ccl.cccid.Version = 系统链版本

sir := container.StartImageReq{CCID: ccid, Builder: ccl.builder, Args: args, Env: env, FilesToUpload: filesToUpload, PrelaunchFunc: preLaunchFunc}

ccl.builder函数　等于：builder := func() (io.Reader, error) { return platforms.GenerateDockerBuild(cds) }
preLaunchFunc函数设置：	chaincodeSupport.runningChaincodes.chaincodeMap[chaincode] = &chaincodeRTEnv{handler: &Handler{readyNotify: notfy}}

vmtype, _ := ccl.ccSupport.getVMType(ccl.cds)　设置vmtype　＝　＂System＂

resp, err := container.VMCProcess(ipcCtxt, vmtype, sir)　函数：

func VMCProcess(ctxt context.Context, vmtype string, req VMCReqIntf) (interface{}, error) 　函数处理：
v = &inproccontroller.InprocVM{}　　返回对象：InprocVM

api.VM接口都有：
type VM interface {
	Deploy(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, reader io.Reader) error
	Start(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, filesToUpload map[string][]byte, builder BuildSpecFactory, preLaunchFunc PrelaunchFunc) error
	Stop(ctxt context.Context, ccid ccintf.CCID, timeout uint, dontkill bool, dontremove bool) error
	Destroy(ctxt context.Context, ccid ccintf.CCID, force bool, noprune bool) error
	GetVMName(ccID ccintf.CCID, format func(string) (string, error)) (string, error)
}

函数：
getCCID()
获取：ccid＝ccintf.CCID{ChaincodeSpec: ccl.cds.ChaincodeSpec, NetworkID: ccl.ccSupport.peerNetworkID, PeerID: ccl.ccSupport.peerID, Version: ccl.cccid.Version}

func (bp CreateImageReq) getCCID() ccintf.CCID {
	return bp.CCID
}

do(ctxt, v)

func (bp CreateImageReq) do(ctxt context.Context, v api.VM) VMCResp {
	var resp VMCResp

	if err := v.Deploy(ctxt, bp.CCID, bp.Args, bp.Env, bp.Reader); err != nil {
		resp = VMCResp{Err: err}
	} else {
		resp = VMCResp{}
	}

	return resp
}

VMCProcess　－－－＞　func VMCProcess(ctxt context.Context, vmtype string, req VMCReqIntf)：
id, err := v.GetVMName(req.getCCID(), nil)　获取id= 系统链码name-version


//Deploy verifies chaincode is registered and creates an instance for it. Currently only one instance can be created
func (vm *InprocVM) Deploy(ctxt context.Context, ccid ccintf.CCID, args []string, env []string, reader io.Reader) error {
	path := ccid.ChaincodeSpec.ChaincodeId.Path  系统链码路径

	ipctemplate := typeRegistry[path]
	if ipctemplate == nil {
		return fmt.Errorf(fmt.Sprintf("%s not registered. Please register the system chaincode in inprocinstances.go", path))
	}

	if ipctemplate.chaincode == nil {
		return fmt.Errorf(fmt.Sprintf("%s system chaincode does not contain chaincode instance", path))
	}

	instName, _ := vm.GetVMName(ccid, nil)
	_, err := vm.getInstance(ctxt, ipctemplate, instName, args, env)

	//FUTURE ... here is where we might check code for safety
	inprocLogger.Debugf("registered : %s", path)

	return err
}


	_, err := vm.getInstance(ctxt, ipctemplate, instName, args, env)
    参数：
    ipctemplate＝type inprocContainer struct {
	chaincode shim.Chaincode　有chaincode　init Invoke接口　　在开始Register已经注册在typeRegistry中了
	running   bool
	args      []string
	env       []string
	stopChan  chan struct{}}
    instName：　系统链码－ｖｅｒｓｉｏｎ
    args：chaincode　-peer.address = 0.0.0.0:7051
    env：CORE_CHAINCODE_ID_NAME="系统链＋version" + CORE_PEER_TLS_ENABLED=true／false + [CORE_TLS_CLIENT_KEY_PATH=] + CORE_CHAINCODE_LOGGING_LEVEL= info + CORE_CHAINCODE_LOGGING_SHIM= waing + CORE_CHAINCODE_LOGGING_FORMAT= "%sf" 


　　在getInstance中初始化系统链实例ｍａｐ对象：instRegistry
  instRegistry[instName是系统链＋version] = ipc
  ipc = &inprocContainer{args: args, env: env, chaincode: ipctemplate.chaincode, stopChan: make(chan struct{})}


______________
总结：
func (s *SupportImpl) Execute　－－－＞　 chaincode.Execute(ctxt, cccid, spec)　－－－＞
theChaincodeSupport.Execute(ctxt, cccid, ccMsg, theChaincodeSupport.executetimeout)　－－－－＞
１：theChaincodeSupport.Launch(ctxt, cccid, spec)　安装
２：theChaincodeSupport.Execute(ctxt, cccid, ccMsg, theChaincodeSupport.executetimeout)　执行

安装：
theChaincodeSupport.Launch　－－－＞　 chaincodeSupport.launchAndWaitForRegister　注册　－－＞launcher.launch(ctxt, notfy)　启动　－－－＞container.VMCProcess(ipcCtxt, vmtype, sir)　注意传递的参数是：StartImageReq　启动参数

StartImageReq　参数的do()函数是：
func (si StartImageReq) do(ctxt context.Context, v api.VM) VMCResp {
	var resp VMCResp
	if err := v.Start(ctxt, si.CCID, si.Args, si.Env, si.FilesToUpload, si.Builder, si.PrelaunchFunc); err != nil {
		resp = VMCResp{Err: err}
	} else {
		resp = VMCResp{}
	}
	return resp
}

v.Start(ctxt, si.CCID, si.Args, si.Env, si.FilesToUpload, si.Builder, si.PrelaunchFunc)

func (vmc *VMController) newVM(typ string) api.VM {
	var (
		v api.VM
	)

	switch typ {
	case DOCKER:
		v = dockercontroller.NewDockerVM()
	case SYSTEM:
		v = &inproccontroller.InprocVM{}　系统链入口
	default:
		v = &dockercontroller.DockerVM{}
	}
	return v
}

调用func (vm *InprocVM) Start　启动系统链：
参数：
instName是系统链码+verison
全局变量instRegistry初始化：
    c = &inprocContainer{args: args, env: env, chaincode: ipctemplate.chaincode, stopChan: make(chan struct{})}
    instRegistry[instName] = ipc

func (vm *InprocVM) Start　－－－＞　func (ipc *inprocContainer) launchInProc
调用：func (ipc *inprocContainer) launchInProc　处理rpc通信

launchInProc－－－＞_shimStartInProc(env, args, ipc.chaincode, ccRcvPeerSend, peerRcvCCSend)
其中_shimStartInProc　执行shim.StartInProc的指针

StartInProc　－－－＞　chatWithPeer(chaincodename, stream, cc)　－－－　＞handler.handleMessage(in)　接受信息并处理　处理状态机

首次发的信息是：
pb.ChaincodeMessage{Type: pb.ChaincodeMessage_REGISTER, Payload: payload}

payload是：
chaincodeID := &pb.ChaincodeID{Name: chaincodename}
payload, err := proto.Marshal(chaincodeID)


状态转换接口：
newChaincodeSupportHandler　？？？？







＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿

Execute函数中调用： theChaincodeSupport.Execute　函数：
其中调用：
	resp, err := theChaincodeSupport.Execute(ctxt, cccid, ccMsg, theChaincodeSupport.executetimeout)
    theChaincodeSupport是全局变量　在chaincode-1.mk介绍过
    
    theChaincodeSupport.runningChaincodes 变量：
    
    type runningChaincodes struct {
	sync.RWMutex
	// chaincode environment for each chaincode
	chaincodeMap map[string]*chaincodeRTEnv　比较重要

	//mark the starting of launch of a chaincode so multiple requests
	//do not attempt to start the chaincode at the same time
	launchStarted map[string]bool
}

type chaincodeRTEnv struct {　
	handler *Handler
}

Execute　－－－＞　chrte, ok := chaincodeSupport.chaincodeHasBeenLaunched(canName)
canName:　系统链码　＋　version

实际是：
chaincodeSupport.runningChaincodes.chaincodeMap[系统链码　＋　version] = chaincodeRTEnv{}

————————————————————————————————————————————————————————————————————————————————————

#### 桥接所有chaincode:
	//this brings up all the chains (including testchainid)
+279　初始化所有chaincode　桥接所有chaincode　需要调研：
	peer.Initialize(func(cid string) {
		logger.Debugf("Deploying system CC, for chain <%s>", cid)
		scc.DeploySysCCs(cid)
	})