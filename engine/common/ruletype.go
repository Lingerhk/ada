package common

import logger "github.com/sirupsen/logrus"

// 规则类型定义, ATT&CK
// https://attack.mitre.org/tactics/enterprise/
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

// 规则威胁等级
const (
	RiskLevelCritical = 5 // 严重
	RiskLevelHigh     = 4 // 高危
	RiskLevelMedium   = 3 // 中危
	RiskLevelLow      = 2 // 低危
	RiskLevelInfo     = 1 // INFO
)

var RiskLevelMap = map[string]int32{
	"info":     RiskLevelInfo, // 仅activity有该level
	"low":      RiskLevelLow,
	"medium":   RiskLevelMedium,
	"high":     RiskLevelHigh,
	"critical": RiskLevelCritical, // 暂时没有该level

	"1": RiskLevelInfo,
	"2": RiskLevelLow,
	"3": RiskLevelMedium,
	"4": RiskLevelHigh,
	"5": RiskLevelCritical,
}

func GetRiskLevel(l string) int32 {
	if lvl, ok := RiskLevelMap[l]; ok {
		return lvl
	}
	logger.Warnf("invalid risk level:%s, will return low level as default.", l)
	return RiskLevelLow
}
