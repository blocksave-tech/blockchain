用户链码实例化：
链码实例化:
peer chaincode instantiate -o orderer.example.com:7050 -C $CHANNEL_NAME -n mycc -l ${LANGUAGE} -v ${VERSION} -c '{"Args":["init","a","100","b","200"]}' -P "OR	('Org1MSP.peer','Org2MSP.peer')"

用户链码是实例化需要给对应的ｃｈａｎｎｅｌ发送交易信息，会用到其他系统链　，先分析cscc系统链码处理


构造ChaincodeSpec：
spec = &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),
		ChaincodeId: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
		Input:       input,
	}

参数：
chaincodePath＝＂＂
chaincodeName＝mycc
chaincodeVersion=1.0
input={"Args":["init","a","100","b","200"]}


构造ChaincodeDeploymentSpec：
chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}

参数：
spec　等于上面的ChaincodeSpec
codePackageBytes等于[]byte　空ｎｉｌ

调用：
prop, _, err := utils.CreateDeployProposalFromCDS(channelID, cds, creator, policyMarshalled, []byte(escc), []byte(vscc), collectionConfigBytes)
参数：
channelID＝mychannel
cds=chaincodeDeploymentSpec
creator 等于本地签名对象
policyMarshalled　等于proto.Marshal(SignaturePolicyEnvelope)数据
即：
common.SignaturePolicyEnvelope{
		Identities: ctx.principals,
		Version:    0,
		Rule:       res.(*common.SignaturePolicy),
	}

escc＝＂＂
vscc＝＂＂
collectionConfigBytes＝ｎｉｌ

构造ChaincodeInvocationSpec:
sccSpec := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type:        peer.ChaincodeSpec_GOLANG,
			ChaincodeId: &peer.ChaincodeID{Name: "lscc"},
			Input:       ccinp}}
ccinp参数：
ccinp = &peer.ChaincodeInput{Args: Args}

其中Args := [][]byte{[]byte(propType), []byte(chainID), b}
即：
Args := [][]byte{[]byte(＂deploy＂), []byte(＂mychannel＂), b}

b=proto.Marshal(chaincodeDeploymentSpec)

CreateDeployProposalFromCDS -- 调用CreateChaincodeProposalWithTxIDNonceAndTransient
CreateChaincodeProposalWithTxIDNonceAndTransient函数内解析：

ccHdrExt := &peer.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId}
其中 cis.ChaincodeSpec.ChaincodeId等于
ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
chaincodePath＝＂＂
chaincodeName＝mycc
chaincodeVersion=1.0


构造Proposal
Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes}
其中
hdrBytes ＝　proto.Marshal(hdr)
hdr＝ &common.Header{ChannelHeader: MarshalOrPanic(&common.ChannelHeader{
		Type:      int32(typ),
		TxId:      txid,
		Timestamp: timestamp,
		ChannelId: chainID,
		Extension: ccHdrExtBytes,
		Epoch:     epoch}),
		SignatureHeader: MarshalOrPanic(&common.SignatureHeader{Nonce: nonce, Creator: creator})}
参数
typ　＝　HeaderType_ENDORSER_TRANSACTION　
txid, err := ComputeProposalTxID(nonce, creator)
timestamp := util.CreateUtcTimestamp()
chainID＝ｍｙｃｈａｎｎｅｌ
Extension　等于proto.Marshal(ccHdrExt)　　ccHdrExt就是上面的peer.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId}
epoch uint64 = 0


ccPropPayloadBytes　＝　Marshal(ccPropPayload)
其中：
ccPropPayload　＝　peer.ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap}

cisBytes＝　proto.Marshal(cis)　ｃｉｓ就是ChaincodeInvocationSpec上面的对象
transientMap　＝　ｎｉｌ

＋＋＋＋＋＋＋＋＋＋＋＋＋＋

构造SignedProposal：
SignedProposal{ProposalBytes: propBytes, Signature: signature},
propBytes＝proto.Marshal(上面构造Proposal)
signature对propBytes　的签名值

＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋
peer节点处理：
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal) (*pb.ProposalResponse, error)

prop, hdrExt, chainID, txid := vr.prop　提案, vr.hdrExt, vr.chainID, vr.txid
参数：
vr.hdrExt　＝　上面的ccHdrExtBytes
等于proto.Marshal(ccHdrExt)　　ccHdrExt就是上面的peer.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId}
其中 cis.ChaincodeSpec.ChaincodeId等于
ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
chaincodePath＝＂＂
chaincodeName＝mycc
chaincodeVersion=1.0

vr.chainID＝ｍｙｃｈａｎｎｅｌ

simulateProposal函数解析：
e.simulateProposal(ctx, chainID, txid, signedProp, prop, hdrExt.ChaincodeId, txsim)
参数：
ctx
chainID＝mychannel
txid　交易ｈａｓｈ
signedProp 提案签名的数据
prop　提案
hdrExt.ChaincodeId　等于ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion}
        其中数值：
        chaincodePath＝＂＂
        chaincodeName＝mycc
        chaincodeVersion=1.0
txsim


函数内调用：
cis, err := putils.GetChaincodeInvocationSpec(prop)　获取ChaincodeInvocationSpec数据

cid等于hdrExt.ChaincodeId
cid.Name　＝　hdrExt.ChaincodeId中的name mycc

if !e.s.IsSysCC(cid.Name) {
cdLedger, err = e.s.GetChaincodeDefinition(ctx, chainID, txid, signedProp, prop, cid.Name, txsim)　　？？
｝

调用：
res, ccevent, err = e.callChaincode(ctx, chainID, version, txid, signedProp, prop, cis, cid, txsim)
内部调用：
scc := e.s.IsSysCC(cid.Name)　ｆａｌｓｅ
res, ccevent, err = e.s.Execute(ctxt, chainID, cid.Name, version, txid, scc, signedProp, prop, cis)


调用：
case *pb.ChaincodeDeploymentSpec:
  return chaincode.Execute(ctxt, cccid, spec)
参数：
cctyp := pb.ChaincodeMessage_INIT
cds, _ = spec.(*pb.ChaincodeDeploymentSpec);
cMsg = ci.ChaincodeSpec.Input　等于ChaincodeInput{Args: Args}
      其中Args := [][]byte{[]byte(propType), []byte(chainID), b}
      即：
      Args := [][]byte{[]byte(＂deploy＂), []byte(＂mychannel＂), b}
      b=proto.Marshal(chaincodeDeploymentSpec)

构造：
	ccMsg, err = createCCMessage(cctyp, cccid.ChainID, cccid.TxID, cMsg)
ChaincodeMessage{Type: typ, Payload: payload, Txid: txid, ChannelId: cid}
typ＝ChaincodeMessage_INIT
payload＝　Marshal（上面的cMsg）
cid＝mychannel

发送：
	resp, err := theChaincodeSupport.Execute(ctxt, cccid, ccMsg, theChaincodeSupport.executetimeout)
参数：
cccid := ccprovider.NewCCContext(cid, name, version, txid, syscc, signedProp, prop)
ccMsg是上面createCCMessage

发送给了lscc 上面createCCMessage数据

入口函数　launchInProc
lscc　fsm接口状态机：
v.FSM = fsm.NewFSM(
		"created",
		fsm.Events{
			{Name: pb.ChaincodeMessage_INIT.String(), Src: []string{"ready"}, Dst: "ready"},
		},
		fsm.Callbacks{
			"before_" + pb.ChaincodeMessage_INIT.String():        func(e *fsm.Event) { v.beforeInit(e) },
		},

func (handler *Handler) beforeInit(e *fsm.Event) {
	chaincodeLogger.Debugf("Entered state %s", handler.FSM.Current())
	msg, ok := e.Args[0].(*pb.ChaincodeMessage)
	if !ok {
		e.Cancel(errors.New("received unexpected message type"))
		return
	}
	chaincodeLogger.Debugf("[%s]Received %s, initializing chaincode", shorttxid(msg.Txid), msg.Type.String())
	if msg.Type.String() == pb.ChaincodeMessage_INIT.String() {　满足条件：
		// Call the chaincode's Run function to initialize
		handler.handleInit(msg)
	}
}

处理chiancode 用户链码实例化：
func (handler *Handler) handleInit(msg *pb.ChaincodeMessage)

stub := new(ChaincodeStub)　构造ChaincodeStub对象
err := stub.init(handler, msg.ChannelId, msg.Txid, input, msg.Proposal)
if nextStateMsg = errFunc(err, nil, stub.chaincodeEvent, "[%s]Init get error response. Sending %s", shorttxid(msg.Txid), pb.ChaincodeMessage_ERROR.String()); nextStateMsg != nil {
  return
}

res := handler.cc.Init(stub)　初始化　调用lscc

返回相应：
nextStateMsg = &pb.ChaincodeMessage{Type: pb.ChaincodeMessage_COMPLETED, Payload: resBytes, Txid: msg.Txid, ChaincodeEvent: stub.chaincodeEvent, ChannelId: stub.ChannelId}

＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋

ProcessProposal　第二次调用e.endorseProposal　做escc 背书检查　调用escc e.callChaincode
调用launch：
vmtype, _ := ccl.ccSupport.getVMType(ccl.cds)
	resp, err := container.VMCProcess(ipcCtxt, vmtype, sir)
  启动编译chaincode　启动运行chaincode 用户链码



end
