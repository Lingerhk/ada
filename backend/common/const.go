package common

// 常量定义
const (
	ROOT_PATH        = "/home/adadmin"    // 项目根路径
	RDX_CRYPT_SECRET = "3a43d7a31b3ca37d" // redis数据加密密钥
)

// 域控制器状态
const (
	DomainStatusRunning = "run"  // 运行中
	DomainStatusStopped = "stop" // 已停止
	DomainStatusInit    = "init" // 初始化中
	DomainStatusErr     = "error"
)

// scanner task status
const (
	ScanTaskStatusRun  = "RUNNING"
	ScanTaskStatusPend = "PENDING"
	ScanTaskStatusFin  = "FINISH"
)

// notify msg_type const
const (
	NotifyMsgSystem   = "system"   // 系统消息
	NotifyMsgBaseline = "baseline" // 主动监测
	NotifyMsgLeak     = "leak"     // 漏洞监测
	NotifyMsgAlert    = "alert"    // 告警事件
)

// NotifyMsgTypeDescMap notify msg_type desc
var NotifyMsgTypeDescMap = map[string]string{
	NotifyMsgSystem:   "系统消息",
	NotifyMsgBaseline: "基线事件",
	NotifyMsgLeak:     "漏洞事件",
	NotifyMsgAlert:    "告警事件",
}

// 规则威胁等级
const (
	RiskLevelCritical = 5 // 严重
	RiskLevelHigh     = 4 // 高危
	RiskLevelMedium   = 3 // 中危
	RiskLevelLow      = 2 // 低危
	RiskLevelInfo     = 1 // INFO
)

// RiskLevelMap notify level desc
var RiskLevelMap = map[int]string{
	RiskLevelCritical: "严重",
	RiskLevelHigh:     "高危",
	RiskLevelMedium:   "中危",
	RiskLevelLow:      "低危",
	RiskLevelInfo:     "信息",
}

// 规则类型定义, ATT&CK
const (
	RT_InitialAccess       = "TA0001" // 初始访问
	RT_Execution           = "TA0002" // 命令执行
	RT_Persistence         = "TA0003" // 持久化
	RT_PrivilegeEscalation = "TA0004" // 权限提升
	RT_DefenseEvasion      = "TA0005" // 防御绕过
	RT_CredentialAccess    = "TA0006" // 凭据操作
	RT_Discovery           = "TA0007" // 渗透信息收集
	RT_LateralMovement     = "TA0008" // 横向移动
	RT_Collection          = "TA0009" // 敏感信息采集
	RT_CommandControl      = "TA0010" // C2控制
	RT_ExfilTration        = "TA0011" // 数据窃取
	RT_Impact              = "TA0012" // 影响
)

var RuleTagMap = map[string]string{
	RT_InitialAccess:       "初始访问",
	RT_Execution:           "命令执行",
	RT_Persistence:         "持久化",
	RT_PrivilegeEscalation: "权限提升",
	RT_DefenseEvasion:      "防御绕过",
	RT_CredentialAccess:    "凭据操作",
	RT_Discovery:           "渗透信息收集",
	RT_LateralMovement:     "横向移动",
	RT_Collection:          "敏感信息采集",
	RT_CommandControl:      "C2控制",
	RT_ExfilTration:        "数据窃取",
	RT_Impact:              "影响",
}

var RuleTypeMap = map[string]string{
	"InitialAccess":       "初始访问",
	"Execution":           "命令执行",
	"Persistence":         "持久化",
	"PrivilegeEscalation": "权限提升",
	"DefenseEvasion":      "防御绕过",
	"CredentialAccess":    "凭据操作",
	"Discovery":           "渗透信息收集",
	"LateralMovement":     "横向移动",
	"Collection":          "敏感信息采集",
	"CommandControl":      "C2控制",
	"ExfilTration":        "数据窃取",
	"Impact":              "影响",
}

// ScanTypeDescMap scanrisk type desc
var ScanTypeDescMap = map[string]string{
	// 基线类型定义:
	"StaleObjects":       "陈旧对象",
	"PrivilegedAccounts": "特权帐户",
	"Trusts":             "信任关系",
	"Anomalies":          "异常现象",

	// 漏洞类型定义:
	"information_leakage":    "信息泄漏",
	"command_execution":      "命令执行",
	"privilege_escalation":   "权限提升",
	"invasion_legacy":        "入侵遗留",
	"improper_configuration": "配置不当",
}

// 系统语言
const (
	LangZh = "ZH"
	LangEn = "EN"
)

// rule type
const (
	RuleTypeFlow   = "flow"
	RuleTypeWinLog = "winlog"
	RuleTypePktLog = "pktlog"
)
