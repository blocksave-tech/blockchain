peer客户端install链码：
＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿
用户链码:
用户链码安装：
peer chaincode install -n mycc -v ${VERSION} -l ${LANGUAGE} -p ${CC_SRC_PATH}

链码实例化:
peer chaincode instantiate -o orderer.example.com:7050 -C $CHANNEL_NAME -n mycc -l ${LANGUAGE} -v ${VERSION} -c '{"Args":["init","a","100","b","200"]}' -P "OR	('Org1MSP.peer','Org2MSP.peer')"


version: 链码版本
langage:　链码使用的语言
cc_sec_path:　链码　源代码的路径

数据结构　ChaincodeSpec：
spec = &pb.ChaincodeSpec{
    Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),　
    ChaincodeId: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
    Input:       input,
}
Type：　使用ｇｏｌａｎｇ版本
ChaincodeId　用户链码　版本　链码名称　链码版本
Input　链码输入参数

ChaincodeDeploymentSpec　数据结构：
chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}

spec　为上面的ChaincodeSpec数据结构
CodePackage　用户链码打包为 .tar.gz　　　二进制链码　代码程序
＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿


发送的数据结构：install
ccinp = &peer.ChaincodeInput{Args: [][]byte{[]byte(propType), b}}
propType　等于＂install＂
ｂ等于上面chaincodeDeploymentSpec　Marshal后的数据

Args：等于＂install＂ 和 chaincodeDeploymentSpec的ｍｓｇ信息
Decorations　＝　ｎｉｌ

构造：
ChaincodeInvocationSpec数据结构：
//wrap the deployment in an invocation spec to lscc...
lsccSpec := &peer.ChaincodeInvocationSpec{
    ChaincodeSpec: &peer.ChaincodeSpec{
        Type:        peer.ChaincodeSpec_GOLANG,
        ChaincodeId: &peer.ChaincodeID{Name: "lscc"},
        Input:       ccinp}}

Type：　等于ChaincodeSpec_GOLANG　＝　１
ChaincodeId：　＂ｌｓｃｃ＂
Input：　输入参数ChaincodeInput



创建一个Proposal对象：
Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes}
１＞Header：
hdrBytes, err := proto.Marshal(hdr)
	hdr := &common.Header{ChannelHeader: MarshalOrPanic(&common.ChannelHeader{
		Type:      int32(typ),　等于HeaderType_ENDORSER_TRANSACTION
		TxId:      txid,　　根据ｃｒｅａｔｏｒ生成的ｎｏｎｅ
		Timestamp: timestamp,　客户端的时间
		ChannelId: chainID,　等于＂＂空
		Extension: ccHdrExtBytes,
		Epoch:     epoch}),　等于０
		SignatureHeader: MarshalOrPanic(&common.SignatureHeader{Nonce: nonce, Creator: creator})}

ccHdrExtBytes　等于：
	ccHdrExt := &peer.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId}
	ccHdrExtBytes, err := proto.Marshal(ccHdrExt)

    cis.ChaincodeSpec.ChaincodeId　等于&peer.ChaincodeID{Name: "lscc"},
    cis　等于ChaincodeInvocationSpec

２＞Payload：
ccPropPayload := &peer.ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap}
ccPropPayloadBytes, err := proto.Marshal(ccPropPayload)

cisBytes等于：
cisBytes, err := proto.Marshal(cis)　其中 cis　等于ChaincodeInvocationSpec
if err != nil {
    return nil, "", err
}

transientMap等于nil
＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿

创建一个SignedProposal对象：
&peer.SignedProposal{ProposalBytes: propBytes, Signature: signature}
１＞其中propBytes等于：
	propBytes, err := GetBytesProposal(prop)
	if err != nil {
		return nil, err
	}
	prop等于：上面的Proposal对象

２＞signature等于
	signature, err := signer.Sign(propBytes)　　对propBytes　提议的签名
	if err != nil {
		return nil, err
	}

＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿

发送　调用rpc接口：
proposalResponse, err := cf.EndorserClient.ProcessProposal(context.Background(), signedProp)
其中signedProp等于SignedProposal
＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿

peer节点处理用户链码接口：
fabric-core-endorser endorser.go代码
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal)
grpc框架获取对端　地址信息：
addr := util.ExtractRemoteAddress(ctx)

其中e *Endorser对象是：
fabric - peer - node start.go
serverEndorser := endorser.NewEndorserServer(privDataDist, &endorser.SupportImpl{})
其中的e对象是Endorser对象
e := &Endorser{
    distributePrivateData: privDist,
    s: s,
}
privDist　函数指针：
privDataDist := func(channel string, txID string, privateData *rwset.TxPvtReadWriteSet) error {
    return service.GetGossipService().DistributePrivateData(channel, txID, privateData)
}

s是endorser.SupportImpl{}


ｐｅｅｒ服务端调用：
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal)
－－＞调用　vr, err := e.preProcess(signedProp)
返回vr结构如下
type validateResult struct {
	prop    *pb.Proposal
	hdrExt  *pb.ChaincodeHeaderExtension
	chainID string
	txid    string
	resp    *pb.ProposalResponse
}

ｐｒｏｐ＝SignedProposal对象ProposalBytes　反序列后的peer.Proposal{}对象
hdrExt　＝　Proposal{Header: hdrBytes对象
chainID　等于lscc
txid 等于客户端的ｎｏｎｅ＋　creator　自动生成的交易ｈａｓｈ
resp　等于ｎｉｌ
＿＿＿＿＿＿＿＿＿＿＿＿

在ProcessProposal函数中：
１＞执行ｉｎｓｔａｌｌ　提议：
	cd, res, simulationResult, ccevent, err := e.simulateProposal(ctx, chainID, txid, signedProp, prop, hdrExt.ChaincodeId, txsim)

２＞在执行ｅｓｃｃ背书：
pResp, err = e.endorseProposal(ctx, chainID, txid, signedProp, prop, res, simulationResult, ccevent, hdrExt.PayloadVisibility, hdrExt.ChaincodeId, txsim, cd)

＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿

用户ｉｎｓｔａｌｌ用户链码　执行：ProcessProposal　－－－　simulateProposal

________________________________________________________________________________


https://www.cnblogs.com/zeyaries/p/7173028.html
http://hyperledger-fabric.readthedocs.io/en/latest/chaincode4noah.html
https://blog.csdn.net/idsuf698987/article/details/78353464

peer chaincode package -n mycc -p github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02 -v 0 -s -S -i "AND('OrgA.admin')" ccpack.out


运行：
https://www.cnblogs.com/zeyaries/p/7173028.html

peer chaincode package -n cc1 -p github.com/chaincode/chaincode_example02/go  -v 0 -s -S -i "AND('OrgA.admin')" ccpack.out

在当前目录生成：
ccpack.out

解析会失败：
curl -X POST --data-binary @ccpack.out http://127.0.0.1:7059/protolator/decode/common.Envelope > ccpack.json

签名打包的chaincode 源代码ccpack.out
peer chaincode signpackage ccpack.out signedccpack.out

chaincode实例化：　instantiate　　chaincode --- instantiate
peer chaincode instantiate -o orderer.example.com:7050 -C $CHANNEL_NAME -n mycc -l ${LANGUAGE} -v ${VERSION} -c '{"Args":["init","a","100","b","200"]}' -P "OR	('Org1MSP.peer','Org2MSP.peer')"

chaincode需要实例化逻辑： 是否还需要打包chaincode源代码字符文件；－－－　这里面有一个golang平台包封装；
chaincode　实例化发送给orderer的tx交易　数据接口lscc vscc验证逻辑　？？？
chaincode 依赖的第三方库，以及怎么编译　编译是在什么时候编译的　问题细化；

chaincode实例化发送给peer,orderer的数据结构是：



ChaincodeSpec数据结构：
spec = &pb.ChaincodeSpec{
    Type:        pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value[chaincodeLang]),
    ChaincodeId: &pb.ChaincodeID{Path: chaincodePath, Name: chaincodeName, Version: chaincodeVersion},
    ／／chaincodePath　等于""  chaincodeName = mycc chaincodeName=1.0
    Input:       input,　初始化参数{"Args":["init","a","100","b","200"]}'
}


ChaincodeDeploymentSpec数据结构构造：
chaincodeDeploymentSpec := &pb.ChaincodeDeploymentSpec{ChaincodeSpec: spec, CodePackage: codePackageBytes}
spec　等于ChaincodeSpec数据结构
codePackageBytes　等于空[]byte
policyMarshalled等于背书策略的Marshal数值

创建提议Proposal: createProposalFromCDS
		Args := [][]byte{[]byte(propType), []byte(chainID), b}
		Args = append(Args, args...)
Args = append(Args, args...) 其中为｛＂deploy＂，＂ｍｙｃｈａｎｎｅｌ＂，ｂ｝
ｂ等于b, err = proto.Marshal(chaincodeDeploymentSpec)

构造：
ccinp = &peer.ChaincodeInput{Args: Args}
类型：
type ChaincodeInput struct {
	Args        [][]byte          `protobuf:"bytes,1,rep,name=args,proto3" json:"args,omitempty"`
	Decorations map[string][]byte 等于nil
}

构造数据类型ChaincodeInvocationSpec：
	lsccSpec := &peer.ChaincodeInvocationSpec{
		ChaincodeSpec: &peer.ChaincodeSpec{
			Type:        peer.ChaincodeSpec_GOLANG,
			ChaincodeId: &peer.ChaincodeID{Name: "lscc"},
			Input:       ccinp}}　ccinp等于上面的ChaincodeInput类型



创建proposal：
 CreateProposalFromCIS(common.HeaderType_ENDORSER_TRANSACTION, chainID, lsccSpec, creator)

构造Proposal数据结构：
Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes}

1>
hdrBytes等于Marshal(hdr)
hdr等于：
	hdr := &common.Header{ChannelHeader: MarshalOrPanic(&common.ChannelHeader{
		Type:      int32(typ),　等于HeaderType_ENDORSER_TRANSACTION
		TxId:      txid,　由creator（ＭＳＰＩＤ　＋　Ｘ５０９证书　＋nonce）生成
        Timestamp: timestamp, 时间
		ChannelId: chainID, mychannel
		Extension: ccHdrExtBytes,
		Epoch:     epoch}), 等于0
		SignatureHeader: MarshalOrPanic(&common.SignatureHeader{Nonce: nonce, Creator: creator})}

ccHdrExtBytes等于:
	ccHdrExt := &peer.ChaincodeHeaderExtension{ChaincodeId: cis.ChaincodeSpec.ChaincodeId} ChaincodeId是cc的name path="" 版本号
	ccHdrExtBytes, err := proto.Marshal(ccHdrExt)
2>
ccPropPayloadBytes:

cisBytes, err := proto.Marshal(cis)  cis就是ChaincodeInvocationSpec CIS的简写
	if err != nil {
		return nil, "", err
	}

ccPropPayload := &peer.ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap} transientMap等于nil
	ccPropPayloadBytes, err := proto.Marshal(ccPropPayload)
	if err != nil {
		return nil, "", err
	}


构造签名的SignedProposal对象:
SignedProposal{ProposalBytes: propBytes, Signature: signature}
propBytes是对Proposal对象的Marshal后的[]byte类型数据;
signature是对propBytes []byte类型的数据签名结果;

________________________________________________________________________________
发送peer背书操作:
proposalResponse, err := cf.EndorserClient.ProcessProposal(context.Background(), signedProp)


__________________________________________________________________________________
发送给orderer的排序交易:
env, err := utils.CreateSignedTx(prop, cf.Signer, proposalResponse)
发送给orderer交易:
cf.BroadcastClient.Send(env) env对象是Envelope数据类型

其中prop是未签名的交易提议;
proposalResponse 是peer背书后的结果;

Envelope数据类型构造:
Envelope{Payload: paylBytes, Signature: sig}

paylBytes数据类型是:common.Payload{Header: hdr, Data: txBytes} 的Marshal后的结果;
sig是对paylBytes签名后的数据;

Header hdr.SignatureHeader数据是
   -----> 原始提议的SignatureHeader: MarshalOrPanic(&common.SignatureHeader{Nonce: nonce, Creator: creator})}数据

Payload: capBytes数据是:
 -----> peer.ChaincodeActionPayload{ChaincodeProposalPayload: propPayloadBytes, Action: cea} 数据Marshal后的结果


________________________________________________________________________________
1> propPayloadBytes
propPayloadBytes等于GetBytesProposalPayloadForTx(pPayl, hdrExt.PayloadVisibility)返回值
pPayl是原始提议Proposal{Header: hdrBytes, Payload: ccPropPayloadBytes} 的Payload Unmarshal后的结果 --->是ChaincodeProposalPayload类型  ChaincodeProposalPayload{Input: cisBytes, TransientMap: transientMap} transientMap等于nil
Input是cisBytes, err := proto.Marshal(cis)  cis就是ChaincodeInvocationSpec CIS的简写
	if err != nil {
		return nil, "", err
	}

hdrExt.PayloadVisibility 等于nil

所以GetBytesProposalPayloadForTx返回返回 --->
peer.ChaincodeProposalPayload{Input: payload.Input, TransientMap: nil} ---> 的Marshal后的数据


________________________________________________________________________________
2> cea数据

	// fill endorsements
	endorsements := make([]*peer.Endorsement, len(resps))
	for n, r := range resps {
		endorsements[n] = r.Endorsement
	}


cea := &peer.ChaincodeEndorsedAction{ProposalResponsePayload: resps[0].Payload, Endorsements: endorsements}

resps[0].Payload 背书返回的数据 ---- 需要调查?
endorsements背书的peer节点 --- 需要调查?
