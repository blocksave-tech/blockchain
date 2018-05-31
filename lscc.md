peer 初始化后的提议 到了peer节点处理流程:
docker run -it  hyperledger/fabric-ccenv:x86_64-1.1.0  bash 

ccenv是所有的用户chaincode第三方库文件:

ccenv 环境中安装的有  ----:
root@5cf931517278:/opt# ls
go  gopath
root@5cf931517278:/opt/gopath/src/github.com/hyperledger/fabric# ls
bccsp  common  core  idemix  msp  protos  vendor

空目录:
root@5cf931517278:/chaincode# ls
input  output


用户chaincode到了fabric进行编译;

模板函数:
fabric - core - container - util dockerutil.go
func ParseDockerfileTemplate(template string) string {
	r := strings.NewReplacer(
		"$(ARCH)", getArch(),
		"$(PROJECT_VERSION)", metadata.Version,
		"$(BASE_VERSION)", metadata.BaseVersion,
		"$(DOCKER_NS)", metadata.DockerNamespace,
		"$(BASE_DOCKER_NS)", metadata.BaseDockerNamespace)

	return r.Replace(template)
}


变量定义在peer 编译的makefile文件中:
// Variables defined by the Makefile and passed in with ldflags
var Version string
var BaseVersion string
var BaseDockerLabel string
var DockerNamespace string
var BaseDockerNamespace string
var Experimental string

Makefile 116行文件: include docker-env.mk  加入环境变量
LDFLAGS = $(METADATA_VAR))

METADATA_VAR = Version=$(PROJECT_VERSION)
METADATA_VAR += BaseVersion=$(BASEIMAGE_RELEASE)
METADATA_VAR += BaseDockerLabel=$(BASE_DOCKER_LABEL)
METADATA_VAR += DockerNamespace=$(DOCKER_NS)
METADATA_VAR += BaseDockerNamespace=$(BASE_DOCKER_NS)
METADATA_VAR += Experimental=$(EXPERIMENTAL)

Version=$(PROJECT_VERSION)  - PROJECT_VERSION=$(BASE_VERSION)  BASE_VERSION = 1.1.1 
BaseVersion=$(BASEIMAGE_RELEASE) - BASEIMAGE_RELEASE=0.4.6
BaseDockerLabel=$(BASE_DOCKER_LABEL) - BASE_DOCKER_LABEL=org.hyperledger.fabric
DockerNamespace=$(DOCKER_NS) - DOCKER_NS ?= hyperledger
BaseDockerNamespace=$(BASE_DOCKER_NS) - BASE_DOCKER_NS ?= hyperledger
Experimental=$(EXPERIMENTAL)   - EXPERIMENTAL ?= true

等于值:
Version=1.1.1
BaseVersion=0.4.6
BaseDockerLabel=org.hyperledger.fabric
DockerNamespace=hyperledger
BaseDockerNamespace=hyperledger
Experimental=true

peer 配置文件:
chaincode:
    builder: $(DOCKER_NS)/fabric-ccenv:$(ARCH)-$(PROJECT_VERSION)
    pull: false
    golang:
        runtime: $(BASE_DOCKER_NS)/fabric-baseos:$(ARCH)-$(BASE_VERSION)
        dynamicLink: false


























