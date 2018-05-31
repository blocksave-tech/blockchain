peer节点数据初始化：
peer.go　－－－＞
	//this brings up all the chains (including testchainid)
	peer.Initialize(func(cid string) {
		logger.Debugf("Deploying system CC, for chain <%s>", cid)
		scc.DeploySysCCs(cid)
	})

fabric-core-peer-peer.go
// ready
func Initialize(init func(string)) 函数解析：
nWorkers = runtime.NumCPU()

－－－ledgermgmt.Initialize(ConfigTxProcessors)
ConfigTxProcessors：
var ConfigTxProcessors = customtx.Processors{
	common.HeaderType_CONFIG:               configTxProcessor,
	common.HeaderType_PEER_RESOURCE_UPDATE: configTxProcessor,
}

configTxProcessor：
var configTxProcessor = newConfigTxProcessor()


















