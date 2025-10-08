package common

const (
	SensorDir        = "C:\\Program Files\\adaegis"
	DefaultBpfFilter = "(tcp) and (port 88 or port 139 or port 445 or port 389) and (not (host %s))" // 默认BPF过滤规则
)

const (
	SensorCmdChannel  = "ada:sensor:cmd_channel" // (pubsub)下发命令通道
	SensorCmdRespKey  = "ada:sensor:cmd_task"    // (kv)服务端可利用该taskId读取结果
	SensorStateQueue  = "ada:sensor:state"       // (list)sensor注册/状态 上报通道
	SensorIDPrefixKey = "ada:sensor:id"          // (hash)sensor info

	SensorLatestVersionKey = "ada:sensor:latest_version" // sensor升级最新version
	SensorLatestBinFileKey = "ada:sensor:latest_binfile" // sensor升级最新binfile
	SensorLatestBinSumKey  = "ada:sensor:latest_binsum"  // sensor升级最新bin file sum
)

// 个sensor plugin名称
const (
	SensorSvcName = "adaegis"

	PlugEvtName = "evt"
	PlugPktName = "pkt"

	PlugRpcFwName     = "rpcfw"
	PlugRpcFwProcName = "rpcFwManager.exe"
	PlugRpcFwSvcName  = "RPC Firewall"

	PlugLdapFwName     = "ldapfw"
	PlugLdapFwProcName = "ldapFwManager.exe"
	PlugLdapFwSvcName  = "LDAP Firewall"
)

// Sensor状态定义
const (
	SensorStatusInit = "Init"
	SensorStatusRun  = "Running"
	SensorStatusStop = "Stopped"
)

// Agent 命令下发通道协议字定义
const (
	// sensor卸载
	T_CMD_SENSOR_REG    = 0x1020 // Sensor注册(仅上行消息)
	T_CMD_UNINSTALL_ALL = 0x1021 // Sensor 卸载

	// 配置相关定义
	T_CONF_STATE  = 0x1030 // sensor状态上报
	T_CONF_UPDATE = 0x1031 // sensor主配置更新

	// Plugin更新
	T_PLUG_CONF_UPDATE = 0x1040 // sensor plugin conf更新
	T_PLUG_BIN_UPDATE  = 0x1041 // sensor plugin bin更新

	// Block阻断策略更新
	T_PLUG_BLOCK_UPDATE = 0x1050 // sensor block policy更新
)
