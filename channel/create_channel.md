创建账本ｃｈａｎｎｅｌ代码分析：

创建一个channel:
peer channel create -o orderer.example.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/channel.tx
或
peer channel create -o orderer.example.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/channel.tx --tls $CORE_PEER_TLS_ENABLED --cafile $ORDERER_CA

生成完后：有$CHANNEL_NAME.block 文件
接着其他ｐｅｅｒ节点执行：
peer channel join -b $CHANNEL_NAME.block

peer　调用接口：　fabric - peer - channel - channelCmd.AddCommand(createCmd(cf))

createCmd函数获取的参数：
channelID＝mychannel
channelTxFile=./channel-artifacts/channel.tx
timeout=5 默认
genesisBlockPath=""

createCmd - create - executeCreate:
从文件/channel-artifacts/channel.tx解析出：createChannelFromConfigTx(channelTxFile)　Envelope结构

Envelope获取Payload　判断头字段参数
payload.Data　获取ConfigUpdateEnvelope
构造签名的：
CreateSignedEnvelope　－－　Envelope　结构
broadcastClient.Send(chCrtEnv)　发送给ｏｒｄｅｒｅｒ

结构从orderer 获取cf.DeliverClient.getSpecifiedBlock(0)　第一个配置块

orderer 接受这个./channel-artifacts/channel.tx　　Envelope签名的结构　启动ｏｒｄｅｒｅｒ 排序逻辑，配置块初始化；

＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋＋
ｐｅｅｒ节点执行：
peer channel join -b $CHANNEL_NAME.block

join　－　executeJoin　获取提议的给ｐｅｅｒ节点，不牵连ｏｒｄｅｒｅｒ

从CHANNEL_NAME.block读取数据：
gb, err := ioutil.ReadFile(genesisBlockPath)

１＞
ChaincodeSpec构造：
spec := &pb.ChaincodeSpec{
		Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]),
		ChaincodeId: &pb.ChaincodeID{Name: "cscc"},
		Input:       input,
	}

  input := &pb.ChaincodeInput{Args: [][]byte{[]byte(＂JoinChain＂), gb}}
  gb就是读取的genesisBlockPath文件

２＞
ChaincodeInvocationSpec构造：
invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}
spec就是上面的ChaincodeSpec对象


构造提议：
prop, _, err = putils.CreateProposalFromCIS(pcommon.HeaderType_CONFIG, "", invocation, creator)

nonce, err := crypto.GetRandomNonce()　随机生成
txid, err := ComputeProposalTxID(nonce, creator)　构造交易txid


peer.Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes}

A>
hdrBytes是hdrBytes, err := proto.Marshal(hdr)
hdr是：
hdr := &common.Header{ChannelHeader: MarshalOrPanic(&common.ChannelHeader{
  Type:      int32(typ),　等于pcommon.HeaderType_CONFIG
  TxId:      txid,　等于上面的交易hash
  Timestamp: timestamp,  时间timestamp := util.CreateUtcTimestamp()本地计算
  ChannelId: chainID,　等于""
  Extension: ccHdrExtBytes,
  Epoch:     epoch}), 等于０
  SignatureHeader: MarshalOrPanic(&common.SignatureHeader{Nonce: nonce, Creator: creator})}

其中ccHdrExtBytes, err := proto.Marshal(ccHdrExt)
ccHdrExt := &peer.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId}　
　　　　　　　　　　　　　等于	ChaincodeId: &pb.ChaincodeID{Name: "cscc"}


B>
ccPropPayloadBytes数据等于：
ccPropPayloadBytes, err := proto.Marshal(ccPropPayload)
ccPropPayload := &peer.ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap}

cisBytes等于：cisBytes, err := proto.Marshal(cis)
transientMap　等于nil
cis等于　invocation := &pb.ChaincodeInvocationSpec{ChaincodeSpec: spec}对象构造的ChaincodeInvocationSpec对象



SignedProposal签名对象构造：
peer.SignedProposal{ProposalBytes: propBytes, Signature: signature}, nil

propBytes, err := GetBytesProposal(prop)
signature, err := signer.Sign(propBytes)

发送给peer节点：
cf.EndorserClient.ProcessProposal(context.Background(), signedProp)

发送给peer cscc链的数据开始了
























































































































end
