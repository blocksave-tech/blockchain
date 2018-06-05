用户发送的install　用户链码数据结构， peer节点是怎么处理的，这章分解：

peer入口函数：
func (e *Endorser) ProcessProposal
调用１函数：
vr, err := e.preProcess(signedProp)　－－　prop, hdr, hdrExt, err := validation.ValidateProposalMessage(signedProp)
其中：
prop: 签名提案中SignedProposal的数据部分
hdr:　hdr, err := utils.GetHeader(prop.Header)　获取头不信息
hdrExt：　头部获取的扩展信息　chaincodeHdrExt, err := utils.GetChaincodeHeaderExtension(hdr)

实际数据内容可以查找chaincode-use.md文件
所以vr, err := e.preProcess(signedProp)返回的数据：
vr:= type validateResult struct {
	prop    *pb.Proposal prop: 签名提案中SignedProposal的数据部分
	hdrExt  *pb.ChaincodeHeaderExtension 　实际是peer.ChaincodeID{Name: "lscc"},
	chainID string 等于空""
	txid    string
	resp    *pb.ProposalResponse
}


调用２：
//1 -- simulate
cd, res, simulationResult, ccevent, err := e.simulateProposal(ctx, chainID, txid, signedProp, prop, hdrExt.ChaincodeId, txsim)
参数：
ctx 含有客户端的地址和端口
chainID　等于""
txid 参数传递的交易ｉｄ
signedProp　　签名的交易提案
prop　提案的数据部分
hdrExt.ChaincodeId　实际就是peer.ChaincodeID{Name: "lscc"},
txsim　目前为空nil

simulateProposal函数内部处理：
cis, err := putils.GetChaincodeInvocationSpec(prop)　获取ChaincodeInvocationSpec对象：
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
参照chaincode-use.md文件
lsccSpec := &peer.ChaincodeInvocationSpec{
    ChaincodeSpec: &peer.ChaincodeSpec{
        Type:        peer.ChaincodeSpec_GOLANG,
        ChaincodeId: &peer.ChaincodeID{Name: "lscc"},
        Input:       ccinp}}

Input：　输入参数ChaincodeInput
&peer.ChaincodeInput{Args: [][]byte{[]byte(＂install＂), b}}

ｂ等于chaincodeDeploymentSpec　Marshal后的数据

pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
1> spec:
    spec = &pb.ChaincodeSpec{
        Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),　
        ChaincodeId: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
        Input:       input,
    }
    Type：　使用ｇｏｌａｎｇ版本
    ChaincodeId　用户链码　版本　链码名称　链码版本
    Input　链码输入参数

2> codePackageBytes:
    用户链码打包为 .tar.gz　
+++++++++++++++++++++++++++++++++
execute the proposal and get simulation results
调用：
res, ccevent, err = e.callChaincode(ctx, chainID, version, txid, signedProp, prop, cis, cid, txsim)
内部调用：
scc := e.s.IsSysCC(cid.Name)　lscc 返回ｔｒｕｅ
res, ccevent, err = e.s.Execute(ctxt, chainID, cid.Name, version, txid, scc, signedProp, prop, cis)
执行：
func (s *SupportImpl) Execute
构造：　cccid := ccprovider.NewCCContext(cid, name, version, txid, syscc, signedProp, prop)
执行：cccid := &CCContext{cid, name, version, txid, syscc, signedProp, prop, canName, nil}
其中
name　＝　ｌｓｃｃ
syscc　ｔｒｕｅ
canName := name + ":" + version　就是lscc+版本

Execute 内部执行：return chaincode.ExecuteChaincode(ctxt, cccid, cis.ChaincodeSpec.Input.Args)
｛
spec, err = createCIS(cccid.Name, args)　构造ChaincodeInvocationSpec对象
解释：
      spec := &pb.ChaincodeInvocationSpec{ChaincodeSpec: &pb.ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: &pb.ChaincodeID{Name: ccname}, Input: &pb.ChaincodeInput{Args: args}}}
      ccname等于lscc
      args 等于：
      ccinp = &peer.ChaincodeInput{Args: [][]byte{[]byte(propType), b}}
      propType　等于＂install＂
      ｂ等于上面chaincodeDeploymentSpec　Marshal后的数据
｝

内部执行：res, ccevent, err = Execute(ctxt, cccid, spec)
内部逻辑：
ci, _ = spec.(*pb.ChaincodeInvocationSpec)
cctyp := pb.ChaincodeMessage_TRANSACTION

获取：cMsg = ci.ChaincodeSpec.Input
cMsg.Decorations = cccid.ProposalDecorations　等于ｎｉｌ

构造：　ChaincodeMessage_TRANSACTION对象
ccMsg, err = createCCMessage(cctyp, cccid.ChainID, cccid.TxID, cMsg)
返回：return &pb.ChaincodeMessage{Type: typ, Payload: payload, Txid: txid, ChannelId: cid}, nil
typ　＝　ChaincodeMessage_TRANSACTION
payload　＝　Marshal(cMsg)
cid　＝　""

调用：
resp, err := theChaincodeSupport.Execute(ctxt, cccid, ccMsg, theChaincodeSupport.executetimeout)
内部解析：
chrte, ok := chaincodeSupport.chaincodeHasBeenLaunched(canName)　根据lscc＋version 后去之前已经注册　部署后的lscc对象chaincodeRTEnv

调用：
if notfy, err = chrte.handler.sendExecuteMessage(ctxt, cccid.ChainID, msg, cccid.SignedProposal, cccid.Proposal)
cccid.ChainID　等于＂＂


lscc 发送系统链码　lscc　系统链码处理数据：
从launchInProc　入口查看chiancode系统链码　lscc　系统链码处理：

v.FSM = fsm.NewFSM(
  "created",
  fsm.Events{
    {Name: pb.ChaincodeMessage_TRANSACTION.String(), Src: []string{"ready"}, Dst: "ready"},
  },
  fsm.Callbacks{
    "before_" + pb.ChaincodeMessage_TRANSACTION.String(): func(e *fsm.Event) { v.beforeTransaction(e) },
  },
)

调用函数：　v.beforeTransaction(e)

func (handler *Handler) beforeTransaction(e *fsm.Event) {
	msg, ok := e.Args[0].(*pb.ChaincodeMessage)
	if !ok {
		e.Cancel(errors.New("Received unexpected message type"))
		return
	}
	chaincodeLogger.Debugf("[%s]Received %s, invoking transaction on chaincode(Src:%s, Dst:%s)", shorttxid(msg.Txid), msg.Type.String(), e.Src, e.Dst)
	if msg.Type.String() == pb.ChaincodeMessage_TRANSACTION.String() {　相等于　进入内部处理
		// Call the chaincode's Run function to invoke transaction
		handler.handleTransaction(msg)
	}
}


函数解析：
func (handler *Handler) handleTransaction(msg *pb.ChaincodeMessage) {


input := &pb.ChaincodeInput{}
unmarshalErr := proto.Unmarshal(msg.Payload, input)　
　－－　获取ccMsg, err = createCCMessage(cctyp, cccid.ChainID, cccid.TxID, cMsg)数据
其中：
ci, _ = spec.(*pb.ChaincodeInvocationSpec)
获取：cMsg = ci.ChaincodeSpec.Input 里面存放的是＂install＂和用户链码的tar未编译的文件；


初始化一个ChaincodeStub对象：
stub := new(ChaincodeStub)
err := stub.init(handler, msg.ChannelId, msg.Txid, input, msg.Proposal)


调用lscc  Invoke函数：
res := handler.cc.Invoke(stub)

lscc系统链码处理：
args := stub.GetArgs()　获取 ci.ChaincodeSpec.Input 里面存放的是＂install＂和用户链码的tar未编译的文件
args[0]＝"install"
args[1]＝用户链码的tar未编译的文件

调用：err := lscc.executeInstall(stub, depSpec)
判断链码名名称是否满足：　lscc.isValidChaincodeName(cds.ChaincodeSpec.ChaincodeId.Name)　
正则表达式：allowedCharsChaincodeName = "[A-Za-z0-9_-]+"
判断版本是否满足正则：allowedCharsVersion       = "[A-Za-z0-9_.+-]+"

非常关键的：从ccpack中解析出链码的byte[]内容：
statedbArtifactsTar, err := ccprovider.ExtractStatedbArtifactsFromCCPackage(ccpack)

安装在本地的文件系统中：
if err = lscc.support.PutChaincodeToLocalStorage(ccpack); err != nil {


返回值：
handleTransaction　构造：
nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_COMPLETED, Payload: resBytes, Txid: msg.Txid, ChaincodeEvent: stub.chaincodeEvent, ChannelId: stub.ChannelId}

handler.triggerNextState(nextStateMsg, true)

func (handler *Handler) triggerNextState(msg *pb.ChaincodeMessage, send bool) {
	handler.nextState <- &nextStateInfo{msg, send}
}

发送给了lscc　handler.nextState

lscc fsm {Name: pb.ChaincodeMessage_COMPLETED.String(), Src: []string{"ready"}, Dst: "ready"},
复位　没有做任何事

同时：　过来写数据ｔｒｅｅ　需要给peer回复　回复的也是ChaincodeMessage_COMPLETED数据　给ｐｅｅｒ
if nsInfo != nil && nsInfo.sendToCC {
			chaincodeLogger.Debugf("[%s]send state message %s", shorttxid(in.Txid), in.Type.String())
			handler.serialSendAsync(in, errc)
		}


peer 收到ChaincodeMessage_COMPLETED
func HandleChaincodeStream(chaincodeSupport *ChaincodeSupport, ctxt context.Context, stream ccintf.ChaincodeStream) error {
	deadline, ok := ctxt.Deadline()
	chaincodeLogger.Debugf("Current context deadline = %s, ok = %v", deadline, ok)
	handler := newChaincodeSupportHandler(chaincodeSupport, stream)
	return handler.processStream()
}

处理消息：
err = handler.handleMessage(in)
－－－＞
if (msg.Type == pb.ChaincodeMessage_COMPLETED || msg.Type == pb.ChaincodeMessage_ERROR) && handler.FSM.Current() == "ready" {
  chaincodeLogger.Debugf("[%s]HandleMessage- COMPLETED. Notify", msg.Txid)
  handler.notify(msg)　通知上层信号　返回
  return nil
}
























end
