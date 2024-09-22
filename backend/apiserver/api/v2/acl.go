// desc: 用户访问权限控制列表 ACL

package v2

import (
	"ada/backend/apiserver/common"
	logger "github.com/sirupsen/logrus"
	"strings"
)

var serviceName = _ADA_serviceDesc.ServiceName

// URL事件映射定义(日志审计的操作映射)
var URLEventMap = map[string]string{
	// 登录页
	"/" + serviceName + "/" + "Login":  "登录",
	"/" + serviceName + "/" + "Logout": "退出登录",

	//threat威胁检测
	"/" + serviceName + "/" + "ActionThreat":          "操作告警事件",
	"/" + serviceName + "/" + "ActionThreatRule":      "修改告警规则",
	"/" + serviceName + "/" + "UpdateThreatConf":      "更新告警配置",
	"/" + serviceName + "/" + "AddSensitiveEntry":     "添加告警敏感条目",
	"/" + serviceName + "/" + "DeleteSensitiveEntry":  "删除告警敏感条目",
	"/" + serviceName + "/" + "AddThreatWhitelist":    "添加告警规则白名单",
	"/" + serviceName + "/" + "DeleteThreatWhitelist": "删除告警规则白名单",
	"/" + serviceName + "/" + "UpdateThreatWhitelist": "更新告警规则白名单",

	// scanrisk主动检测
	"/" + serviceName + "/" + "AddScanTask":     "添加扫描任务",
	"/" + serviceName + "/" + "RecheckScanTask": "执行立即检测任务",
	"/" + serviceName + "/" + "DeleteScanTask":  "删除扫描任务",
	"/" + serviceName + "/" + "SetScanConf":     "修改扫描配置",
	"/" + serviceName + "/" + "UpdateScanConf":  "更新配置详情",
	"/" + serviceName + "/" + "UpdateScanTmpl":  "更新扫描模版",
	"/" + serviceName + "/" + "DeleteScanTmpl":  "删除扫描模版",
	"/" + serviceName + "/" + "AddScanTmpl":     "添加扫描模版",

	// 系统管理
	//域服务器配置
	"/" + serviceName + "/" + "AddDomain":        "添加域配置",
	"/" + serviceName + "/" + "UpdateDomain":     "修改域配置",
	"/" + serviceName + "/" + "TestDomain":       "测试域连接",
	"/" + serviceName + "/" + "DeleteDomain":     "删除域配置",
	"/" + serviceName + "/" + "UpdateDomainData": "同步域信息",

	// 传感器管理
	"/" + serviceName + "/" + "UpdateSensor":        "更新域控传感器",
	"/" + serviceName + "/" + "DownloadSensor":      "下载域控传感器",
	"/" + serviceName + "/" + "CmdSensor":           "执行域控传感器操作",
	"/" + serviceName + "/" + "UpdateSensorVersion": "更新域控传感器版本",

	// 个人中心
	"/" + serviceName + "/" + "UpdateUserPassword": "修改密码",
	"/" + serviceName + "/" + "UpdateUser":         "修改用户信息",
	"/" + serviceName + "/" + "UpdateAvatar":       "上传头像",
	"/" + serviceName + "/" + "EnableMfa":          "开启登录二次校验",
	"/" + serviceName + "/" + "DisableMfa":         "关闭登录二次校验",

	// 子账户管理
	"/" + serviceName + "/" + "AddUser":            "创建账户",
	"/" + serviceName + "/" + "UpdateUser":         "更新账户信息",
	"/" + serviceName + "/" + "UpdateUserPassword": "更新账户密码",
	"/" + serviceName + "/" + "DeleteUser":         "删除账户",
	"/" + serviceName + "/" + "EnableMfa":          "开启二次认证",
	"/" + serviceName + "/" + "EnableMfa":          "禁用二次认证",
	"/" + serviceName + "/" + "ResetPasswordReq":   "重置密码",

	// 系统信息
	"/" + serviceName + "/" + "UpdateCompanyIcon":    "更新产品Logo",
	"/" + serviceName + "/" + "UpdateNtpAddress":     "更新NTP地址",
	"/" + serviceName + "/" + "UpdateSystemLanguage": "修改系统语言",
	"/" + serviceName + "/" + "UpdateLicense":        "更新授权许可",
	"/" + serviceName + "/" + "NetworkDebug":         "执行网络调试",

	// 日志审计
	"/" + serviceName + "/" + "ExportAuditLog": "导出审计日志",
	"/" + serviceName + "/" + "DeleteAuditLog": "清空审计日志",

	// 通知模块
	"/" + serviceName + "/" + "UpdateNotifyConf": "修改通知信息",
	"/" + serviceName + "/" + "EnableNotifyConf": "开关通知配置",
	"/" + serviceName + "/" + "TestNotifyConf":   "测试通知信息",

	// 报表报告
	"/" + serviceName + "/" + "AddExportTask":    "添加导出任务",
	"/" + serviceName + "/" + "DeleteExportTask": "删除导出任务",
}

// URL事件脱敏参数定义
var URLEventMaskingMap = map[string][]string{
	"/" + serviceName + "/" + "Login":              []string{"password"},
	"/" + serviceName + "/" + "AddUser":            []string{"password"},
	"/" + serviceName + "/" + "UpdateUser":         []string{"password"},
	"/" + serviceName + "/" + "UpdateUserPassword": []string{"oldPassword", "newPassword"},
	"/" + serviceName + "/" + "AddDomain":          []string{"password"},
	"/" + serviceName + "/" + "UpdateDomain":       []string{"password"},
	"/" + serviceName + "/" + "TestDomain":         []string{"password"},
	"/" + serviceName + "/" + "ResetPassword":      []string{"newPassword"},
	"/" + serviceName + "/" + "UpdateNotifyConf":   []string{"metadata"},
}

var moduleMap = map[string][]string{
	// 风险大盘
	"RiskMarket": []string{"StatsAlertActivity", "StatsRiskAssets", "StatsAlertEvents", "StatsScanEvents", "StatsAssets", "AlarmAnalysis", "RiskTrend", "ListStatsAlertName", "ListStatsAlertType"},
	//告警列表
	"ThreatEventFind": []string{"ListThreatEvent", "ListThreatActivity", "ListThreatRawLog", "GetRuleInfo", "GetDCNameList", "GetTarget", "GetDomainFromAlert", "ListThreatEventSearch", "ListRuleTypes", "StateAlertEventByRule", "GetThreatEventByUniqueID"},
	// 告警列表操作
	"ThreatEventOperating": []string{"UpdateThreatEvent", "ExportThreatEvent"},
	// 主动检测
	"Scanner": []string{"GetScanRule", "ScanInspection", "GetScanTaskState", "GetScanScore", "SetCronTask", "ListCronTask", "EventList", "EventDetails",
		"LastScanInfo", "StopScan", "ListOnlineDomain", "ListDomainByScanEvent", "ExportScanEvent", "GetInstanceList", "ListTaskManagerGroup",
		"DetailTaskManagerGroup", "DeleteTaskManagerGroup", "ProtectInfo"},
	// 事件列表
	"ThreatList": []string{"ListRuleTypes", "ListDomainByThreat", "ListDCByThreat", "ListTypeByThreat", "ListLevelByThreat", "GetThreatList"},
	// 敏感组配置,蜜罐账户
	"SensitiveGroup": []string{"AddDomainEntry", "DeleteDomainEntry", "ListDomainEntry"},
	// 告警配置
	"Kerberos": []string{"GetKerberosConf", "UpdateKerberosConf", "ListKerberosConf"},
	// 白名单管理
	"RuleWhite": []string{"AddRuleWhitelist", "DeleteRuleWhitelist", "UpdateRuleWhitelist", "GetRuleWhitelist", "ListRuleWhitelist", "GetRuleWhitelistInfo", "ListWhiteField", "GetWhiteFieldValue"},
	// 联动配置
	"AlertConf": []string{"GetAlertConf", "SetAlertConf", "TestEmailSend"},
	// 通知模块
	"NotifyConf": []string{"ListNotifyConf", "UpdateNotifyConf", "UpdateNotifyConfEnable", "GetNotifyConfInfo", "ListNotifyTarget", "TestEmail", "SelectOptionNotify"},
	//域服务器配置
	"Domain": []string{"ListDomain", "AddDomain", "TestDomain", "UpdateDomain", "DeleteDomain", "GetDomainObjectInfo", "UpdateDomainData", "GetDomainInfo", "SetMsRCP"},
	// 运维管理员的域配置
	"OpsDomain": []string{"ListDomain", "AddDomain", "TestDomain", "UpdateDomain", "GetDomainObjectInfo", "UpdateDomainData", "GetDomainInfo", "SetMsRCP"},
	// 安全管理员的域配置
	"SecDomain": []string{"ListDomain", "GetDomainObjectInfo", "GetDomainInfo"},
	//传感器管理
	"Agent": []string{"UpdateAgent", "CmdAgent", "DownloadAgent", "DownCertificate",
		"DeleteAgent", "ListGateway", "ListWecBeat", "UpdateAgentVersion", "DeleteWecBeat", "GetDCList", "AddWecConf", "WecBeatInfo", "ListWecBeatEventInfo"},
	// 日志审计
	"AuditLog":       []string{"ListAuditLog", "ExportAuditLog"},
	"AuditLogDelete": []string{"DeleteAuditLog"},
	// 系统信息
	"System": []string{"GetSystemInfo", "DownloadSystemLog", "GetSystemLog", "GetLicence", "UpdateLicence", "UpdateSystemIcon", "GetSystemIcon", "NetworkDiag", "SetSystemTime"},
	// 帮助中心
	"Help": []string{},
	// 个人中心
	"User": []string{"Login", "Logout", "ListUser", "AddUser", "UpdateUser", "UpdateUserPassword",
		"CheckMfa", "EnableMfa", "DisableMfa", "UpdateAvatar", "GetPwdUpdateTm"},
	"AccountManagement": []string{"DeleteUser", "ResetPassword"},
	//	消息模块
	"MessageNotify": []string{"ListNotify", "UpdateNotify", "AddNotifyEmailConf", "DeleteNotifyEmailConf", "UpdateNotifyEmailConf", "ListNotifyEmailConf", "StatsNotify"},
	// 事件报表
	"EventReport": []string{"GenerateEventReport", "ListEventReport", "StatusEventReport", "DownloadEventReport", "DeleteEventReport"},
	// 通用接口
	"All": {"ListAgent", "ListStatsAlertCount", "ListDomainNameForEventList", "ListDomainNameFromAgent", "ListDomain", "ListWhiteField", "ListDomainName", "GetDomainObject", "GetTaskState", "ListThreatEventSearch", "StateAlertEventByRule", "ListScanPluginType"},
	// 数据检索
	"Search": {"ListSearchLogEvent", "GetSearchLogField", "GetSearchChartData", "GetSearchFieldInfo", "AddSearchTemplate", "ListSearchTemplate", "DeleteSearchTemplate"},
	// 资产相关接口
	"Assets": {"ListAssetsUser", "ListAssetsComputer", "ListAssetsGroup", "GetAssetsDetailsByAlert", "ListGroupByAssets",
		"GetAssetsActivities", "GetAssetsEntry", "GetAssetsLabel", "GetAssetsLabelInfo", "ListUsersSensitiveGroup", "StatsAssetsActivitiesLevel", "GetAssetsSensitiveGroupLabelInfo"},
	// 攻击路径
	"AttackPath": {"ListAttackPath", "ExportAttackPath"},
	// 漏洞检测
	"LeakEvent": {"ScanLeakEvent", "StatsLeakEvent", "ListLeakEvent", "ListScanPlugin", "UpdateScanPluginEnable", "UpdateScanPluginMetaData", "GetScanLeakEventStatus"},
}

func moduleMapJoin(strList ...string) string {
	str := ""
	for _, v := range strList {
		str += strings.Join(moduleMap[v], ",") + ","
	}
	return str
}

var UserACL = map[string]string{
	common.RoleMgr: moduleMapJoin("All", "AccountManagement", "Agent", "AlertConf", "AttackPath", "AuditLog", "AuditLogDelete", "Domain", "EventReport", "LeakEvent", "Help", "Honeypot", "Kerberos", "MessageNotify", "RiskMarket", "RuleWhite", "Scanner", "SensitiveGroup", "System", "ThreatEventFind", "ThreatEventOperating", "ThreatList", "User", "Search", "Assets", "SetSystemTime"),
	common.RoleSec: moduleMapJoin("All", "Agent", "AlertConf", "AttackPath", "AuditLog", "AuditLogDelete", "EventReport", "Help", "Honeypot", "Kerberos", "LeakEvent", "MessageNotify", "RiskMarket", "RuleWhite", "Scanner", "SensitiveGroup", "SecDomain", "System", "ThreatEventFind", "ThreatEventOperating", "ThreatList", "User", "Search", "Assets"),
	common.RoleOps: moduleMapJoin("All", "Agent", "AlertConf", "AttackPath", "AuditLog", "AuditLogDelete", "EventReport", "Help", "LeakEvent", "MessageNotify", "OpsDomain", "RiskMarket", "Scanner", "System", "ThreatEventFind", "ThreatList", "User", "Search", "Assets"),
}

func CheckUserAccess(role, fullMethod string) bool {
	paths := strings.SplitN(fullMethod, "/", 3)
	if len(paths) != 3 {
		return false
	}
	if paths[1] != serviceName {
		return false
	}

	acl, ok := UserACL[role]
	if !ok {
		logger.Warnf("invalid user role:%s, ignored.", role)
		return false
	}

	for _, method := range strings.Split(acl, ",") {
		if method == paths[2] {
			return true
		}
	}

	return false
}
