用户链码初始化：

命令：
peer chaincode instantiate -o orderer.example.com:7050 -C $CHANNEL_NAME -n mycc -l ${LANGUAGE} -v ${VERSION} -c '{"Args":["init","a","100","b","200"]}' -P "OR	('Org1MSP.peer','Org2MSP.peer')" >&log.txt

其中：
CHANNEL_NAME　隧道channel
chaincode 名称是ｍｙｃｃ
LANGUAGE　＝　＂golang＂ chaincode使用的语言
VERSION　＝　chaincode 使用的版本

数据结构：
１＞ChaincodeSpec：
spec = &pb.ChaincodeSpec{
    Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),　
    ChaincodeId: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
    Input:       input,
}

Type　等于golang函数　等于1
ChaincodeId　等于&pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},　path等于空,名称＼班额本
Input 等于input := &pb.ChaincodeInput{}　如下等于初始化参数
－－
type ChaincodeInput struct {
	Args        [][]byte          `protobuf:"bytes,1,rep,name=args,proto3" json:"args,omitempty"`
	Decorations map[string][]byte `protobuf:"bytes,2,rep,name=decorations" json:"decorations,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

２＞ChaincodeDeploymentSpec：
chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
spec等于ChaincodeSpec
codePackageBytes　等于var codePackageBytes []byte　空对象


构造Proposal对象：
createProposalFromCDS(chainID, cds, creator, "deploy", policy, escc, vscc)
其中
chainID＝mychannel
cds=等于上面的ChaincodeDeploymentSpec对象
creator peer　中签名者
policy　＂＂
escc　＂＂
vscc　＂＂

构造ChaincodeInvocationSpec结构对象：
lsccSpec := &peer.ChaincodeInvocationSpec{
ChaincodeSpec: &peer.ChaincodeSpec{
Type:        peer.ChaincodeSpec_GOLANG,
ChaincodeId: &peer.ChaincodeID{Name: "lscc"},
Input:       ccinp}}

－－
ChaincodeInvocationSpec　中　ChaincodeSpec　值　如上赋值
IdGenerationAlg等于空
－－

Type　等于ｇｏｌａｎｇ　为１
ChaincodeId　等于＂ｌｓｃｃ＂
Input　等于ccinp = &peer.ChaincodeInput{Args: Args}
Ａｒｇｓ等于＂deploy＂，＂mychannel＂,proto.Marshal(上面的ChaincodeDeploymentSpec对象)
Decorations等于空

type ChaincodeInput struct {
	Args        [][]byte          `protobuf:"bytes,1,rep,name=args,proto3" json:"args,omitempty"`
	Decorations map[string][]byte `protobuf:"bytes,2,rep,name=decorations" json:"decorations,omitempty" protobuf_key:"bytes,1,opt,name=key" protobuf_val:"bytes,2,opt,name=value,proto3"`
}

＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿
Proposal对象构造：
peer.Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes}
其中：

１＞　Header　hdrBytes等于
hdr := &common.Header{ChannelHeader: MarshalOrPanic(&common.ChannelHeader{
    Type:      int32(typ),　等于HeaderType_ENDORSER_TRANSACTION
    TxId:      txid,　计算的ｔｘｉｄ
    Timestamp: timestamp,　客户端时间
    ChannelId: chainID,　　ｍｙｃｈａｎｎｅｌ
    Extension: ccHdrExtBytes,　　Marshal－－ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId}　
    Epoch:     epoch}),　＝　０
    SignatureHeader: MarshalOrPanic(&common.SignatureHeader{Nonce: nonce, Creator: creator})}

    其中ｃｈｉａｎｃｏｄｅｉｄ等于：pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},　用户链码路径　名称　版本
hdrBytes, err := proto.Marshal(hdr)

２＞　Payload: ccPropPayloadBytes等于：
ccPropPayload := &peer.ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap}
ccPropPayloadBytes, err := proto.Marshal(ccPropPayload)

Input: cisBytes等于上面的ChaincodeInvocationSpec结构对象
TransientMap: transientMap等于ｎｉｌ

＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿
构造peer.SignedProposal对象：

peer.SignedProposal{ProposalBytes: propBytes, Signature: signature}

ProposalBytes: propBytes是对Proposal对象构造的Marshal
Signature: signature　对Proposal对象的签名


＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿
调用ｐｅｅｒ的ProcessProposal　ｒｐｃ远程调用函数：
	proposalResponse, err := cf.EndorserClient.ProcessProposal(context.Background(), signedProp)
    signedProp为SignedProposal对象
＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿
ｐｅｅｒ节点处理
ProcessProposal函数处理:
--vr, err := e.preProcess(signedProp) 函数处理：
