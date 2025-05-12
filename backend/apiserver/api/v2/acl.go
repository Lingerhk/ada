// desc: 用户访问权限控制列表 ACL

package v2

import (
	"ada/backend/apiserver/common"
	"strings"

	logger "github.com/sirupsen/logrus"
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
	"/" + serviceName + "/" + "AddThreatBlock":        "添加威胁阻断",
	"/" + serviceName + "/" + "UpdateThreatBlock":     "更新威胁阻断",
	"/" + serviceName + "/" + "DeleteThreatBlock":     "删除威胁阻断",

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
	"/" + serviceName + "/" + "EnableMfa":          "开启/关闭登录二次校验",
	"/" + serviceName + "/" + "DisableMfa":         "开启/关闭登录二次校验",

	// 子账户管理
	"/" + serviceName + "/" + "AddUser":       "创建账户",
	"/" + serviceName + "/" + "DeleteUser":    "删除账户",
	"/" + serviceName + "/" + "ResetPassword": "重置密码",

	// 系统信息
	"/" + serviceName + "/" + "UpdateProductIcon":    "更新产品Logo",
	"/" + serviceName + "/" + "UpdateNtpAddress":     "更新NTP地址",
	"/" + serviceName + "/" + "UpdateSystemLanguage": "修改系统语言",
	"/" + serviceName + "/" + "SetSystemStatsCfg":    "更新系统监控配置",
	"/" + serviceName + "/" + "UpdateLicense":        "更新授权许可",
	"/" + serviceName + "/" + "NetworkDebug":         "执行网络调试",

	// 日志审计
	"/" + serviceName + "/" + "ExportAuditLog": "导出审计日志",
	"/" + serviceName + "/" + "DeleteAuditLog": "清空审计日志",

	// 通知模块
	"/" + serviceName + "/" + "UpdateNotifyConf": "修改通知配置",
	"/" + serviceName + "/" + "EnableNotifyConf": "开关通知配置",
	"/" + serviceName + "/" + "TestNotifyConf":   "测试通知配置",
	"/" + serviceName + "/" + "UpdateNotify":     "更新通知状态",

	// 报表报告
	"/" + serviceName + "/" + "AddExportTask":    "添加导出任务",
	"/" + serviceName + "/" + "DeleteExportTask": "删除导出任务",
}

// URL事件脱敏参数定义
var URLEventMaskingMap = map[string][]string{
	"/" + serviceName + "/" + "Login":              {"password"},
	"/" + serviceName + "/" + "AddUser":            {"password"},
	"/" + serviceName + "/" + "UpdateUser":         {"password"},
	"/" + serviceName + "/" + "UpdateUserPassword": {"oldPassword", "newPassword"},
	"/" + serviceName + "/" + "AddDomain":          {"password"},
	"/" + serviceName + "/" + "UpdateDomain":       {"password"},
	"/" + serviceName + "/" + "TestDomain":         {"password"},
	"/" + serviceName + "/" + "ResetPassword":      {"newPassword"},
	"/" + serviceName + "/" + "UpdateNotifyConf":   {"metadata"},
}

var moduleMap = map[string][]string{
	// User Management & Personal Center
	"User": {
		"Login", "Logout", "ListUser", "AddUser", "UpdateUser", "UpdateUserPassword",
		"DeleteUser", "UserExists", "CheckMfa", "EnableMfa", "DisableMfa", "UpdateAvatar",
		"ResetPassword", "GetPwdUpdateTm",
	},
	// Domain Management
	"Domain": {
		"ListDomain", "AddDomain", "TestDomain", "UpdateDomain", "DeleteDomain", "UpdateDomainData",
	},
	// Sensor Management
	"Sensor": {
		"ListSensor", "UpdateSensor", "DownloadSensor", "CmdSensor", "UpdateSensorVersion",
	},
	// System Management & Information
	"System": {
		"GetSystemInfo", "GetProductIcon", "UpdateProductIcon", "UpdateNtpAddress",
		"UpdateSystemLanguage", "GetSystemStats", "SetSystemStatsCfg", "GetLicense",
		"UpdateLicense", "NetworkDebug",
	},
	// Notification Configuration
	"NotifyConf": {
		"ListNotifyConf", "UpdateNotifyConf", "EnableNotifyConf", "TestNotifyConf",
	},
	// Export Task Management
	"ExportTask": {
		"ListExportTask", "AddExportTask", "DeleteExportTask",
	},
	// Notification Center
	"Notify": {
		"ListNotify", "UpdateNotify", "StatsNotify",
	},
	// Audit Log
	"AuditLog": {
		"ListAuditLog",
	},
	// Threat Detection (Events, Rules, Config, Whitelists, Blocking etc.)
	"Threat": {
		"ListThreat", "GetThreatNames", "ListThreatRule", "ActionThreatRule", "GetThreat",
		"ActionThreat", "ListActivity", "GetActivityNames", "GetActivity", "ListThreatConf",
		"UpdateThreatConf", "ListSensitiveEntry", "AddSensitiveEntry", "ListDomainEntry",
		"DeleteSensitiveEntry", "ListThreatWhitelist", "GetThreatWhitelistField",
		"AddThreatWhitelist", "UpdateThreatWhitelist", "DeleteThreatWhitelist",
		"ListThreatBlock", "AddThreatBlock", "UpdateThreatBlock", "DeleteThreatBlock",
	},
	// Threat Detection Dashboard
	"ThreatDashboard": {
		"ThreatTops", "ThreatTrends",
	},
	// Scan Risk (Baseline, Leak, WeakPwd)
	"ScanRisk": {
		"ListBaseline", "GetBaseline", "ListLeak", "ListWeakPwd",
	},
	// Scan Risk Dashboard
	"ScanRiskDashboard": {
		"ScanRiskStats",
	},
	// Scan Task Management
	"ScanTask": {
		"ListScanTask", "GetScanTask", "AddScanTask", "RecheckScanTask", "DeleteScanTask",
	},
	// Scan Configuration
	"ScanConf": {
		"ListScanConf", "SetScanConf", "GetScanConf", "GetScanTmplNames", "UpdateScanConf",
	},
	// Scan Templates & Plugins
	"ScanTmpl": {
		"ListScanTmpl", "GetScanTmpl", "UpdateScanTmpl", "DeleteScanTmpl", "AddScanTmpl",
		"ListScanPlugin",
	},
	// Main Dashboard
	"Dashboard": {
		"DashboardStats", "DashboardTrends", "DashboardLogStats",
	},
}

func moduleMapJoin(modules ...string) string {
	var methods []string
	for _, moduleName := range modules {
		if moduleMethods, ok := moduleMap[moduleName]; ok {
			methods = append(methods, moduleMethods...)
		} else {
			logger.Warnf("ACL moduleMap referenced non-existent module: %s", moduleName)
		}
	}
	return strings.Join(methods, ",")
}

// UserACL defines the allowed methods for each role based on the moduleMap.
var UserACL = map[string]string{
	// Manager has access to all modules.
	common.RoleMgr: moduleMapJoin(
		"User", "Domain", "Sensor", "System", "NotifyConf", "ExportTask", "Notify",
		"AuditLog", "Threat", "ThreatDashboard", "ScanRisk", "ScanRiskDashboard",
		"ScanTask", "ScanConf", "ScanTmpl", "Dashboard",
	),
	// Security role has access to threat/scan related modules, dashboards, audit, notifications, and limited system/user access.
	common.RoleSec: moduleMapJoin(
		"Threat", "ThreatDashboard", "ScanRisk", "ScanRiskDashboard", "ScanTask",
		"ScanConf", "ScanTmpl", "Dashboard", "ExportTask", "Notify",
		"AuditLog", "System", // System access might need further refinement (read-only?)
		"Sensor", "Domain", // Sensor/Domain access might need refinement (read-only?)
		"User", // Assumed personal user access + relevant read operations
	),
	// Operations role has access to system/sensor/domain management, audit, notifications, dashboard, and personal user access.
	common.RoleOps: moduleMapJoin(
		"Domain", "Sensor", "System", "NotifyConf", "ExportTask", "Notify",
		"Threat", "ThreatDashboard", "ScanRisk", "ScanRiskDashboard", "ScanTask",
		"ScanConf", "ScanTmpl", "Dashboard", "AuditLog",
		"User", // Assumed personal user access + relevant read operations
	),
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
