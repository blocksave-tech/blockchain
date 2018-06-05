Evaluate函数:

第一调用处：

//policyEvalutor interface provides the interfaces for policy evaluation
type policyEvaluator interface {
	PolicyRefForAPI(resName string) string
	Evaluate(polName string, id []*common.SignedData) error
}

//policyEvaluatorImpl implements policyEvaluator
type policyEvaluatorImpl struct {
	bundle resourcesconfig.Resources
}

func (pe *policyEvaluatorImpl) PolicyRefForAPI(resName string) string {
	pm := pe.bundle.APIPolicyMapper()
	if pm == nil {
		return ""
	}

	return pm.PolicyRefForAPI(resName)
}

func (pe *policyEvaluatorImpl) Evaluate(polName string, sd []*common.SignedData) error {
	policy, ok := pe.bundle.PolicyManager().GetPolicy(polName)
	if !ok {
		return PolicyNotFound(polName)
	}

	return policy.Evaluate(sd)
}


第二调用出：

// Evaluate takes a set of SignedData and evaluates whether this set of signatures satisfies the policy
func (imp *implicitMetaPolicy) Evaluate(signatureSet []*cb.SignedData) error {
	logger.Debugf("This is an implicit meta policy, it will trigger other policy evaluations, whose failures may be benign")
	remaining := imp.threshold

	defer func() {
		if remaining != 0 {
			// This log message may be large and expensive to construct, so worth checking the log level
			if logger.IsEnabledFor(logging.DEBUG) {
				var b bytes.Buffer
				b.WriteString(fmt.Sprintf("Evaluation Failed: Only %d policies were satisfied, but needed %d of [ ", imp.threshold-remaining, imp.threshold))
				for m := range imp.managers {
					b.WriteString(m)
					b.WriteString(".")
					b.WriteString(imp.subPolicyName)
					b.WriteString(" ")
				}
				b.WriteString("]")
				logger.Debugf(b.String())
			}
		}
	}()

	for _, policy := range imp.subPolicies {
		if policy.Evaluate(signatureSet) == nil {
			remaining--
			if remaining == 0 {
				return nil
			}
		}
	}
	if remaining == 0 {
		return nil
	}
	return fmt.Errorf("Failed to reach implicit threshold of %d sub-policies, required %d remaining", imp.threshold, remaining)
}

第三实现出：
type policyLogger struct {
	policy     Policy
	policyName string
}

func (pl *policyLogger) Evaluate(signatureSet []*cb.SignedData) error {
	if logger.IsEnabledFor(logging.DEBUG) {
		logger.Debugf("== Evaluating %T Policy %s ==", pl.policy, pl.policyName)
		defer logger.Debugf("== Done Evaluating %T Policy %s", pl.policy, pl.policyName)
	}

	err := pl.policy.Evaluate(signatureSet)
	if err != nil {
		logger.Debugf("Signature set did not satisfy policy %s", pl.policyName)
	} else {
		logger.Debugf("Signature set satisfies policy %s", pl.policyName)
	}
	return err
}

第四实现处：
fabric - common - cauthdsl - policy.go

// NewPolicy creates a new policy based on the policy bytes
func (pr *provider) NewPolicy(data []byte) (policies.Policy, proto.Message, error) {
	sigPolicy := &cb.SignaturePolicyEnvelope{}
	if err := proto.Unmarshal(data, sigPolicy); err != nil {
		return nil, nil, fmt.Errorf("Error unmarshaling to SignaturePolicy: %s", err)
	}

	if sigPolicy.Version != 0 {
		return nil, nil, fmt.Errorf("This evaluator only understands messages of version 0, but version was %d", sigPolicy.Version)
	}

	compiled, err := compile(sigPolicy.Rule, sigPolicy.Identities, pr.deserializer)
	if err != nil {
		return nil, nil, err
	}

	return &policy{
		evaluator:    compiled,
		deserializer: pr.deserializer,
	}, sigPolicy, nil

}

SignaturePolicyEnvelope　结构入口查看逻辑处理？？？


type policy struct {
	evaluator    func([]*cb.SignedData, []bool) bool
	deserializer msp.IdentityDeserializer
}

// Evaluate takes a set of SignedData and evaluates whether this set of signatures satisfies the policy
func (p *policy) Evaluate(signatureSet []*cb.SignedData) error {
	if p == nil {
		return fmt.Errorf("No such policy")
	}

	ok := p.evaluator(deduplicate(signatureSet, p.deserializer), make([]bool, len(signatureSet)))
	if !ok {
		return errors.New("signature set did not satisfy policy")
	}
	return nil
}

＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿

SignaturePolicy 数据结构解析：
fabric-protos-common-policies.proto

message SignaturePolicy {
    message NOutOf {　　＃＃＃内部定义NOutOf　数据对象
        int32 n = 1;
        repeated SignaturePolicy rules = 2;　＃＃对自身数据对象的重复　相当多维数组
    }　＃这个ｍｓｇ仅仅是定义一个内部结构

    oneof Type {　　＃＃＃选择其中一个数据对象
        int32 signed_by = 1;
        NOutOf n_out_of = 2;
    }
}
＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿

生成的ｇｏ文件：
type SignaturePolicy struct {
	// Types that are valid to be assigned to Type:
	//	*SignaturePolicy_SignedBy
	//	*SignaturePolicy_NOutOf_
	Type isSignaturePolicy_Type `protobuf_oneof:"Type"`
}


type isSignaturePolicy_Type interface {　　＃＃接口定义
	isSignaturePolicy_Type()
}

如下结构体对其继承：

type SignaturePolicy_SignedBy struct {
	SignedBy int32 `protobuf:"varint,1,opt,name=signed_by,json=signedBy,oneof"`
}
type SignaturePolicy_NOutOf_ struct {
	NOutOf *SignaturePolicy_NOutOf `protobuf:"bytes,2,opt,name=n_out_of,json=nOutOf,oneof"`
}

func (*SignaturePolicy_SignedBy) isSignaturePolicy_Type() {}
func (*SignaturePolicy_NOutOf_) isSignaturePolicy_Type()  {}

func (m *SignaturePolicy) GetType() isSignaturePolicy_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *SignaturePolicy) GetSignedBy() int32 {
	if x, ok := m.GetType().(*SignaturePolicy_SignedBy); ok {
		return x.SignedBy
	}
	return 0
}

处理逻辑：
func (pr *provider) NewPolicy(data []byte) (policies.Policy, proto.Message, error) {
sigPolicy := &cb.SignaturePolicyEnvelope{}
sigPolicy.Rule　类型就是＊SignaturePolicy



解析背书策略的验证入口：
AND('A.member', 'B.member')
FromString("AND('A.member', 'B.member')")　此函数


函数返回是：
func FromString(policy string) (*common.SignaturePolicyEnvelope, error) { 函数
	p := &common.SignaturePolicyEnvelope{
		Identities: ctx.principals,　数值为：｛ROLE，Org1MSP｝，｛ROLE，Org2MSP｝
		Version:    0,
		Rule:       res.(*common.SignaturePolicy),　
        ｒｅｓ为：n_out_of:<n:2 rules:<signed_by:0 > rules:<signed_by:1 > >
	}
｝

说明：
Identities为principals数组：｛ROLE，Org1MSP｝，｛ROLE，Org2MSP｝
　　　其中ＲＯＬＥ为角色　type MSPPrincipal_Classification int32类型
   　　Org1MSP　为Principal类型　[]byte类型

Rule为SignaturePolicy类型
其中ｏｒ关系为：
n_out_of:<n:1 rules:<signed_by:0 > rules:<signed_by:1 > >

ａｎｄ关系为：
n_out_of:<n:2 rules:<signed_by:0 > rules:<signed_by:1 > >


＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿


返回SignaturePolicyEnvelope对象：
type SignaturePolicyEnvelope struct {
	Version    int32                   `protobuf:"varint,1,opt,name=version" json:"version,omitempty"`
	Rule       *SignaturePolicy        `protobuf:"bytes,2,opt,name=rule" json:"rule,omitempty"`
	Identities []*common1.MSPPrincipal `protobuf:"bytes,3,rep,name=identities" json:"identities,omitempty"`
}


lscc - support.go :
ｌｓｃｃ验证交易签名：
func (s *supportImpl) CheckInstantiationPolicy(signedProp *pb.SignedProposal, chainName string, instantiationPolicy []byte) error {
	err = instPol.Evaluate(sd)





bug问题导致分析
ｐｅｅｒ执行：
peer channel create -o orderer.example.com:7050 -c $CHANNEL_NAME -f ./channel-artifacts/channel.tx

报错:
InitCmdFactory - Endorser and orderer connectionst initialized -
./peer/channel/channel.go:157:  logger.Infof("Endorser and orderer connections initialized")

got unexpected status FORBIDDEN --- ssss

./peer/common/broadcastclient.go:55:            return errors.Errorf("got unexpected status: %v -- %s", msg.Status, msg.Info)


  ./common/policies/implicitmeta.go:101:  return fmt.Errorf("Failed to reach implicit threshold of %d sub-policies, required %d remaining", imp.threshold, remaining)

代码：
func (imp *implicitMetaPolicy) Evaluate(signatureSet []*cb.SignedData) error {
   logger.Debugf("This is an implicit meta policy, it will trigger other policy evaluations, whose failures may be benign")
   remaining := imp.threshold

       return fmt.Errorf("Failed to reach implicit threshold of %d sub-policies, required %d remaining", imp.threshold, remaining)
}

什么原因导致：？？？





orderer　报的错误是：
2018-05-21 07:10:43.061 UTC [cauthdsl] func2 -> DEBU 3ad 0xc4208662e8 signed by 0 principal evaluation starts (used [false])
2018-05-21 07:10:43.061 UTC [cauthdsl] func2 -> DEBU 3ae 0xc4208662e8 principal evaluation fails
2018-05-21 07:10:43.061 UTC [cauthdsl] func1 -> DEBU 3af 0xc4208662e8 gate 1526886643061224459 evaluation fails
2018-05-21 07:10:43.061 UTC [policies] Evaluate -> DEBU 3b0 Signature set did not satisfy policy /Channel/Application/Org3MSP/Readers
2018-05-21 07:10:43.061 UTC [policies] Evaluate -> DEBU 3b1 == Done Evaluating *cauthdsl.policy Policy /Channel/Application/Org3MSP/Readers
2018-05-21 07:10:43.061 UTC [policies] func1 -> DEBU 3b2 Evaluation Failed: Only 0 policies were satisfied, but needed 1 of [ Org1MSP.Readers Org2MSP.Readers Org3MSP.Readers ]
2018-05-21 07:10:43.061 UTC [policies] Evaluate -> DEBU 3b3 Signature set did not satisfy policy /Channel/Application/Readers
2018-05-21 07:10:43.061 UTC [policies] Evaluate -> DEBU 3b4 == Done Evaluating *policies.implicitMetaPolicy Policy /Channel/Application/Readers
2018-05-21 07:10:43.061 UTC [policies] func1 -> DEBU 3b5 Evaluation Failed: Only 0 policies were satisfied, but needed 1 of [ Orderer.Readers Application.Readers ]
2018-05-21 07:10:43.061 UTC [policies] Evaluate -> DEBU 3b6 Signature set did not satisfy policy /Channel/Readers
2018-05-21 07:10:43.061 UTC [policies] Evaluate -> DEBU 3b7 == Done Evaluating *policies.implicitMetaPolicy Policy /Channel/Readers
2018-05-21 07:10:43.061 UTC [common/deliver] deliverBlocks -> WARN 3b8 [channel: mychannel] Client authorization revoked for deliver request from 172.21.0.5:42972: Failed to reach implicit threshold of 1 sub-policies, required 1 remaining: permission denied
2018-05-21 07:10:43.061 UTC [common/deliver] Handle -> DEBU 3b9 Waiting for new SeekInfo from 172.21.0.5:42972
2018-05-21 07:10:43.061 UTC [common/deliver] Handle -> DEBU 3ba Attempting to read seek info message from 172.21.0.5:42972
2018-05-21 07:10:43.072 UTC [common/deliver] Handle -> WARN 3bb Error reading from 172.21.0.7:55900: rpc error: code = Canceled desc = context canceled
2018-05-21 07:10:43.072 UTC [orderer/common/server] func1 -> DEBU 3bc Closing Deliver stream
2018-05-21 07:10:43.074 UTC [orderer/common/server] Deliver -> DEBU 3bd Starting new Deliver handler
2018-05-21 07:10:43.074 UTC [common/deliver] Handle -> DEBU 3be Starting new deliver loop for 172.21.0.7:55912
2018-05-21 07:10:43.074 UTC [common/deliver] Handle -> DEBU 3bf Attempting to read seek info message from 172.21.0.7:55912
2018-05-21 07:10:43.074 UTC [policies] Evaluate -> DEBU 3c0 == Evaluating *policies.implicitMetaPolicy Policy /Channel/Readers ==
2018-05-21 07:10:43.074 UTC [policies] Evaluate -> DEBU 3c1 This is an implicit meta policy, it will trigger other policy evaluations, whose failures may be benign
2018-05-21 07:10:43.074 UTC [policies] Evaluate -> DEBU 3c2 == Evaluating *policies.implicitMetaPolicy Policy /Channel/Orderer/Readers ==
2018-05-21 07:10:43.074 UTC [policies] Evaluate -> DEBU 3c3 This is an implicit meta policy, it will trigger other policy evaluations, whose failures may be benign
2018-05-21 07:10:43.074 UTC [policies] Evaluate -> DEBU 3c4 == Evaluating *cauthdsl.policy Policy /Channel/Orderer/OrdererOrg/Readers ==
2018-05-21 07:10:43.074 UTC [msp] DeserializeIdentity -> INFO 3c5 Obtaining identity
2018-05-21 07:10:43.075 UTC [msp/identity] newIdentity -> DEBU 3c6 Creating identity instance for cert -----BEGIN CERTIFICATE-----
MIICKDCCAc+gAwIBAgIRAPtWbpxwUQQ7ZgKllvpEf6gwCgYIKoZIzj0EAwIwczEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh
Lm9yZzEuZXhhbXBsZS5jb20wHhcNMTgwNTIxMDcwNTMzWhcNMjgwNTE4MDcwNTMz
WjBqMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzENMAsGA1UECxMEcGVlcjEfMB0GA1UEAxMWcGVlcjEub3Jn
MS5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABIq+ooDukD6l
HeuQnXykFUHBTEw+DFsaHHUG3D5nd00+8e+m+WLwxHFlgJ9x7GixvDaoyQ9J/OAG
hOXgJXpxaOujTTBLMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMCsGA1Ud
IwQkMCKAIMZDMaHDOrUhG24m4aKtiQG9yAvtwpBa1ZRa2WoJCbgWMAoGCCqGSM49
BAMCA0cAMEQCIHyVb2HYiTQv17ZIsSuByBNOHVyl3HUrzalKj6DT790WAiBX+LCx
NFa9/rl2mcXBlaryWUqGNFNlROsLtmCoAVIsmQ==
-----END CERTIFICATE-----
2018-05-21 07:10:43.075 UTC [cauthdsl] deduplicate -> ERRO 3c7 Principal deserialization failure (the supplied identity is not valid: x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "ca.org1.example.com")) for identity 0a074f7267314d535012aa062d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949434b44434341632b6741774942416749524150745762707877555151375a674b6c6c76704566366777436759494b6f5a497a6a304541774977637a454c0a4d416b474131554542684d4356564d78457a415242674e5642416754436b4e6862476c6d62334a7561574578466a415542674e564241635444564e68626942470a636d467559326c7a593238784754415842674e5642416f54454739795a7a45755a586868625842735a53356a623230784844416142674e5642414d5445324e680a4c6d39795a7a45755a586868625842735a53356a623230774868634e4d5467774e5449784d4463774e544d7a5768634e4d6a67774e5445344d4463774e544d7a0a576a42714d517377435159445651514745774a56557a45544d4245474131554543424d4b5132467361575a76636d3570595445574d4251474131554542784d4e0a5532467549455a795957356a61584e6a627a454e4d4173474131554543784d456347566c636a45664d4230474131554541784d576347566c636a457562334a6e0a4d53356c654746746347786c4c6d4e766254425a4d424d4742797147534d34394167454743437147534d343941774548413049414249712b6f6f44756b44366c0a486575516e58796b465548425445772b44467361484855473344356e6430302b38652b6d2b574c777848466c674a3978374769787644616f7951394a2f4f41470a684f58674a587078614f756a5454424c4d41344741315564447745422f775145417749486744414d42674e5648524d4241663845416a41414d437347413155640a4977516b4d434b41494d5a444d6148444f7255684732346d34614b74695147397941767477704261315a526132576f4a436267574d416f4743437147534d34390a42414d43413063414d45514349487956623248596954517631375a497353754279424e4f4856796c334855727a616c4b6a36445437393057416942582b4c43780a4e4661392f726c326d6358426c617279575571474e464e6c524f734c746d436f415649736d513d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a
2018-05-21 07:10:43.075 UTC [cauthdsl] func1 -> DEBU 3c8 0xc42015a238 gate 1526886643075262987 evaluation starts
2018-05-21 07:10:43.075 UTC [cauthdsl] func2 -> DEBU 3c9 0xc42015a238 signed by 0 principal evaluation starts (used [false])
2018-05-21 07:10:43.075 UTC [cauthdsl] func2 -> DEBU 3ca 0xc42015a238 principal evaluation fails
2018-05-21 07:10:43.075 UTC [cauthdsl] func1 -> DEBU 3cb 0xc42015a238 gate 1526886643075262987 evaluation fails
2018-05-21 07:10:43.075 UTC [policies] Evaluate -> DEBU 3cc Signature set did not satisfy policy /Channel/Orderer/OrdererOrg/Readers
2018-05-21 07:10:43.075 UTC [policies] Evaluate -> DEBU 3cd == Done Evaluating *cauthdsl.policy Policy /Channel/Orderer/OrdererOrg/Readers
2018-05-21 07:10:43.075 UTC [policies] func1 -> DEBU 3ce Evaluation Failed: Only 0 policies were satisfied, but needed 1 of [ OrdererOrg.Readers ]
2018-05-21 07:10:43.075 UTC [policies] Evaluate -> DEBU 3cf Signature set did not satisfy policy /Channel/Orderer/Readers
2018-05-21 07:10:43.075 UTC [policies] Evaluate -> DEBU 3d0 == Done Evaluating *policies.implicitMetaPolicy Policy /Channel/Orderer/Readers
2018-05-21 07:10:43.075 UTC [policies] Evaluate -> DEBU 3d1 == Evaluating *policies.implicitMetaPolicy Policy /Channel/Application/Readers ==
2018-05-21 07:10:43.075 UTC [policies] Evaluate -> DEBU 3d2 This is an implicit meta policy, it will trigger other policy evaluations, whose failures may be benign
2018-05-21 07:10:43.075 UTC [policies] Evaluate -> DEBU 3d3 == Evaluating *cauthdsl.policy Policy /Channel/Application/Org1MSP/Readers ==
2018-05-21 07:10:43.075 UTC [msp] DeserializeIdentity -> INFO 3d4 Obtaining identity
2018-05-21 07:10:43.075 UTC [msp/identity] newIdentity -> DEBU 3d5 Creating identity instance for cert -----BEGIN CERTIFICATE-----
MIICKDCCAc+gAwIBAgIRAPtWbpxwUQQ7ZgKllvpEf6gwCgYIKoZIzj0EAwIwczEL


主要错误是：
2018-05-21 07:10:43.075 UTC [cauthdsl] deduplicate -> ERRO 3d6 Principal deserialization failure (the supplied identity is not valid: x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "ca.org1.example.com")) for identity 0a074f7267314d535012aa062d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949434b44434341632b6741774942416749524150745762707877555151375a674b6c6c76704566366777436759494b6f5a497a6a304541774977637a454c0a4d416b474131554542684d4356564d78457a415242674e5642416754436b4e6862476c6d62334a7561574578466a415542674e564241635444564e68626942470a636d467559326c7a593238784754415842674e5642416f54454739795a7a45755a586868625842735a53356a623230784844416142674e5642414d5445324e680a4c6d39795a7a45755a586868625842735a53356a623230774868634e4d5467774e5449784d4463774e544d7a5768634e4d6a67774e5445344d4463774e544d7a0a576a42714d517377435159445651514745774a56557a45544d4245474131554543424d4b5132467361575a76636d3570595445574d4251474131554542784d4e0a5532467549455a795957356a61584e6a627a454e4d4173474131554543784d456347566c636a45664d4230474131554541784d576347566c636a457562334a6e0a4d53356c654746746347786c4c6d4e766254425a4d424d4742797147534d34394167454743437147534d343941774548413049414249712b6f6f44756b44366c0a486575516e58796b465548425445772b44467361484855473344356e6430302b38652b6d2b574c777848466c674a3978374769787644616f7951394a2f4f41470a684f58674a587078614f756a5454424c4d41344741315564447745422f775145417749486744414d42674e5648524d4241663845416a41414d437347413155640a4977516b4d434b41494d5a444d6148444f7255684732346d34614b74695147397941767477704261315a526132576f4a436267574d416f4743437147534d34390a42414d43413063414d45514349487956623248596954517631375a497353754279424e4f4856796c334855727a616c4b6a36445437393057416942582b4c43780a4e4661392f726c326d6358426c617279575571474e464e6c524f734c746d436f415649736d513d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a

./common/cauthdsl/cauthdsl.go:89:                       cauthdslLogger.Debugf("%p signed by %d principal evaluation starts (used %v)", signedData, t.SignedBy, used)
---->
0xc42015a248 signed by 0 principal evaluation starts (used [false])



查看channl.tx文件
 cat channel.tx

�

����"	mychannel�
�
	mychannel;)

Application

Org2MSP

Org1MSP

Consortium��

Application�

Org2MSP

Org1MSP$

Capabilities


V1_1Admins""
iters
WritersAdmins""
Admins

AdminsAdmins""
aders
ReadersAdmins*Admins"

Consortium
SampleConsortium

＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿＿
查看正常的channel.tx文件：
 cat channel.tx

�

����"	mychannel�
�
	mychannel;)

Application

Org1MSP

Org2MSP

Consortium��

Application�

Org1MSP

Org2MSP$

Capabilities


V1_1Admins""
Admins

AdminsAdmins""
aders
ReadersAdmins""
iters
WritersAdmins*Admins"

Consortium
SampleConsortium

区别是：
Org1MSP
Org2MSP
一个前一个后？？？？？？？？？？？？？？？？？？？？／


有时正常顺序也会错：
:29:51.892 UTC [cauthdsl] func1 -> DEBU 94c 0xc4201800f0 gate 1526887791892465217 evaluation fails
2018-05-21 07:29:51.892 UTC [policies] Evaluate -> DEBU 94d Signature set did not satisfy policy /Channel/Application/Org1MSP/Readers
2018-05-21 07:29:51.892 UTC [policies] Evaluate -> DEBU 94e == Done Evaluating *cauthdsl.policy Policy /Channel/Application/Org1MSP/Readers
2018-05-21 07:29:51.892 UTC [policies] Evaluate -> DEBU 94f == Evaluating *cauthdsl.policy Policy /Channel/Application/Org2MSP/Readers ==
2018-05-21 07:29:51.892 UTC [msp] DeserializeIdentity -> INFO 950 Obtaining identity
2018-05-21 07:29:51.892 UTC [msp/identity] newIdentity -> DEBU 951 Creating identity instance for cert -----BEGIN CERTIFICATE-----
MIICKTCCAc+gAwIBAgIRAI+D55mWYMvpZZ9USmM2zcowCgYIKoZIzj0EAwIwczEL
MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG
cmFuY2lzY28xGTAXBgNVBAoTEG9yZzIuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh
Lm9yZzIuZXhhbXBsZS5jb20wHhcNMTgwNTIxMDcyNDI5WhcNMjgwNTE4MDcyNDI5
WjBqMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN
U2FuIEZyYW5jaXNjbzENMAsGA1UECxMEcGVlcjEfMB0GA1UEAxMWcGVlcjAub3Jn
Mi5leGFtcGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJ1FlzsMGDSc
QkO26kitLP8RYVoO1sJaKiwZmykvVtNrK6XP7LrdE00G4MPUbb+MWK3frpYBP8e0
2ce1VeTz0iWjTTBLMA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMCsGA1Ud
IwQkMCKAINVIptLvGx6q71BmpzmxKhH+8/4SjN+posU20lOm/O9kMAoGCCqGSM49
BAMCA0gAMEUCIQD7eZyZSQk23JzFQb744q+8Lsp5l8n4jh4qYuN7xGCrdAIgfmqe
/7JnlwFjnaJ0G23gfi/+qs+wnDiks9gTFEPv4+E=
-----END CERTIFICATE-----
2018-05-21 07:29:51.893 UTC [cauthdsl] deduplicate -> ERRO 952 Principal deserialization failure (the supplied identity is not valid: x509: certificate signed by unknown authority (possibly because of "x509: ECDSA verification failure" while trying to verify candidate authority certificate "ca.org2.example.com")) for identity 0a074f7267324d535012aa062d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949434b54434341632b67417749424167495241492b4435356d57594d76705a5a3955536d4d327a636f77436759494b6f5a497a6a304541774977637a454c0a4d416b474131554542684d4356564d78457a415242674e5642416754436b4e6862476c6d62334a7561574578466a415542674e564241635444564e68626942470a636d467559326c7a593238784754415842674e5642416f54454739795a7a49755a586868625842735a53356a623230784844416142674e5642414d5445324e680a4c6d39795a7a49755a586868625842735a53356a623230774868634e4d5467774e5449784d4463794e4449355768634e4d6a67774e5445344d4463794e4449350a576a42714d517377435159445651514745774a56557a45544d4245474131554543424d4b5132467361575a76636d3570595445574d4251474131554542784d4e0a5532467549455a795957356a61584e6a627a454e4d4173474131554543784d456347566c636a45664d4230474131554541784d576347566c636a417562334a6e0a4d69356c654746746347786c4c6d4e766254425a4d424d4742797147534d34394167454743437147534d34394177454841304941424a31466c7a734d474453630a516b4f32366b69744c50385259566f4f31734a614b69775a6d796b7656744e724b365850374c726445303047344d505562622b4d574b336672705942503865300a326365315665547a3069576a5454424c4d41344741315564447745422f775145417749486744414d42674e5648524d4241663845416a41414d437347413155640a4977516b4d434b41494e564970744c76477836713731426d707a6d784b68482b382f34536a4e2b706f735532306c4f6d2f4f396b4d416f4743437147534d34390a42414d43413067414d45554349514437655a795a53516b32334a7a465162373434712b384c7370356c386e346a68347159754e377847437264414967666d71650a2f374a6e6c77466a6e614a304732336766692f2b71732b776e44696b7339675446455076342b453d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a
2018-05-21 07:29:51.893 UTC [cauthdsl] func1 -> DEBU 953 0xc420180100 gate 1526887791893095961 evaluation starts
2018-05-21 07:29:51.893 UTC [cauthdsl] func2 -> DEBU 954 0xc420180100 signed by 0 principal evaluation starts (used [false])
2018-05-21 07:29:51.893 UTC [cauthdsl] func2 -> DEBU 955 0xc420180100 principal evaluation fails
2018-05-21 07:29:51.893 UTC [cauthdsl] func1 -> DEBU 956 0xc420180100 gate 1526887791893095961 evaluation fails
2018-05-21 07:29:51.893 UTC [policies] Evaluate -> DEBU 957 Signature set did not satisfy policy /Channel/Application/Org2MSP/Readers
2018-05-21 07:29:51.893 UTC [policies] Evaluate -> DEBU 958 == Done Evaluating *cauthdsl.policy Policy /Channel/Application/Org2MSP/Readers
2018-05-21 07:29:51.893 UTC [policies] func1 -> DEBU 959 Evaluation Failed: Only 0 policies were satisfied, but needed 1 of [ Org3MSP.Readers Org1MSP.Readers Org2MSP.Readers ]


错误信息主要是：
2018-05-21 07:10:43.061 UTC [policies] func1 -> DEBU 3b2 Evaluation Failed: Only 0 policies were satisfied, but needed 1 of [ Org1MSP.Readers Org2MSP.Readers Org3MSP.Readers ]
