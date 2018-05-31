
It has these top-level messages:
	CollectionConfigPackage
	CollectionConfig
	StaticCollectionConfig
	CollectionPolicyConfig
	CollectionCriteria
	LastConfig
	Metadata
	MetadataSignature
	Header
	ChannelHeader
	SignatureHeader
	Payload
	Envelope
	Block
	BlockHeader
	BlockData
	BlockMetadata
	ConfigEnvelope
	ConfigGroupSchema
	ConfigValueSchema
	ConfigPolicySchema
	Config
	ConfigUpdateEnvelope
	ConfigUpdate
	ConfigGroup
	ConfigValue
	ConfigPolicy
	ConfigSignature
	HashingAlgorithm
	BlockDataHashingStructure
	OrdererAddresses
	Consortium
	Capabilities
	Capability
	BlockchainInfo
	Policy
	SignaturePolicyEnvelope
	SignaturePolicy
	ImplicitMetaPolicy
*/


tools:
应该可以解析的数据类型：

common.LastConfig
common.Metadata
common.MetadataSignature
common.Header
common.ChannelHeader
common.SignatureHeader
common.Payload
common.Envelope
common.Block
common.BlockHeader
common.BlockData
common.BlockMetadata
    
    
解析数据：
curl -X POST --data-binary @genesis.block http://127.0.0.1:7059/protolator/decode/common.Block > genesis.json

curl -X POST --data-binary @mychannel.block http://127.0.0.1:7059/protolator/decode/common.Block > mychannel.json


curl -X POST --data-binary @channel.tx http://127.0.0.1:7059/protolator/decode/common.Envelope > channel.json

curl -X POST --data-binary @Org1MSPanchors.tx http://127.0.0.1:7059/protolator/decode/common.Envelope > Org1MSPanchors.json



curl -X POST --data-binary @Org2MSPanchors.tx http://127.0.0.1:7059/protolator/decode/common.Envelope > Org2MSPanchors.json



默认签名值：
func GetDefaultSigner() (msp.SigningIdentity, error) {
	signer, err := mspmgmt.GetLocalMSP().GetDefaultSigningIdentity()
	if err != nil {
		return nil, errors.WithMessage(err, "error obtaining the default signing identity")
	}
	return signer, err
}



