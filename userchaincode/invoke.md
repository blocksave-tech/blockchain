调用用户链码：
peer chaincode invoke -o orderer.example.com:7050 -C $CHANNEL_NAME -n mycc -c '{"Args":["invoke","a","b","10"]}'

ｐｅｅｒ Invoke参数：
chaincodeCtorJSON＝{"Args":["invoke","a","b","10"]}
channelID＝$CHANNEL_NAME mychannel
chaincodeName = mycc
transient＝＂＂
OrderingEndpoint＝　orderer.example.com:7050

chaincodeInvoke - InitCmdFactory(true, true)
                - chaincodeInvokeOrQuery


ChaincodeSpec构造：
spec = &pb.ChaincodeSpec{
  Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),
  ChaincodeId: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
  Input:       input,
}
参数：
chaincodePath＝＂＂
chaincodeName＝mycc
chaincodeVersion＝＂＂

input：
input := &pb.ChaincodeInput{}
	if err := json.Unmarshal([]byte(chaincodeCtorJSON), &input); err != nil {
		return spec, fmt.Errorf("Chaincode argument error: %s", err)
	}
chaincodeCtorJSON就是"Args":["invoke","a","b","10"]


调用：chaincodeInvokeOrQuery　->
proposalResp, err := ChaincodeInvokeOrQuery(
  spec,　就是上面的ChaincodeSpec
  channelID,　＝mychannel
  invoke,　＝　ｔｒｕｅ
  cf.Signer,
  cf.EndorserClient,
  cf.BroadcastClient)

函数内部：
invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
funcName := "invoke"
creator, err := signer.Serialize()

内部调用ChaincodeInvokeOrQuery：
１＞　构造提议
prop, _, err = putils.CreateChaincodeProposalWithTransient(pcommon.HeaderType_ENDORSER_TRANSACTION, cID, invocation, creator, tMap)
内部调用　：CreateChaincodeProposalWithTxIDNonceAndTransient(txid, typ, chainID, cis, nonce, creator, transientMap)
参数：
txid, err := ComputeProposalTxID(nonce, creator)
typ=pcommon.HeaderType_ENDORSER_TRANSACTION
chainID=mychannel
cis 等于上面的　invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
creator　＝　 signer.Serialize()
transientMap　＝　ｎｉｌ

提案数据Proposal：
Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes}
Ａ＞
hdrBytes＝ := proto.Marshal(hdr)
hdr := &common.Header{ChannelHeader: MarshalOrPanic(&common.ChannelHeader{
		Type:      int32(typ),　等于HeaderType_ENDORSER_TRANSACTION
		TxId:      txid,　　等于txid, err := ComputeProposalTxID(nonce, creator)
		Timestamp: timestamp, 等于本地时间timestamp := util.CreateUtcTimestamp()
		ChannelId: chainID,　等于mychannel
		Extension: ccHdrExtBytes,
		Epoch:     epoch}),　等于０
		SignatureHeader: MarshalOrPanic(&common.SignatureHeader{Nonce: nonce, Creator: creator})}

其中：
ccHdrExtBytes等于proto.Marshal(ccHdrExt)
ccHdrExt等于ccHdrExt := &peer.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId}

其中 cis.ChaincodeSpec.ChaincodeId等于：
ChaincodeId: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
各个参数等于：
chaincodePath＝＂＂
chaincodeName＝ｍｙｃｃ
chaincodeVersion＝＂＂

Ｂ＞
ccPropPayloadBytes, err := proto.Marshal(ccPropPayload)

ccPropPayload等于：
ccPropPayload := &peer.ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap}

cisBytes等于：
cisBytes, err := proto.Marshal(cis)

cis等于上面的　invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}

构造SignedProposal结构：
signedProp　＝　peer.SignedProposal{ProposalBytes: propBytes, Signature: signature}

propBytes等于proto.Marshal(prop　Proposal　上面的提议)
signature　＝　 signer.Sign(propBytes)

＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋
发送给ｐｅｅｒ节点背书：
proposalResp, err = endorserClient.ProcessProposal(context.Background(), signedProp)
感觉应该是启动用户端chaincode链码　－　
用户链码编译　－　启动　－　调用ｉｎｖｏｋｅ函数　逻辑处理梳理　

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
发给ｏｒｄｅｒｅｒ背书结果：
env, err := putils.CreateSignedTx(prop, signer, proposalResp)




































end
