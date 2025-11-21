package worker

import (
	"ada/backend/common"
)

var notifyMsgTypeDescMap = map[string]map[string]string{
	common.NotifyMsgSystem: {
		common.LangZh: "系统消息",
		common.LangEn: "System",
	},
	common.NotifyMsgBaseline: {
		common.LangZh: "基线事件",
		common.LangEn: "Baseline",
	},
	common.NotifyMsgLeak: {
		common.LangZh: "漏洞事件",
		common.LangEn: "Vulnerability",
	},
	common.NotifyMsgAlert: {
		common.LangZh: "告警事件",
		common.LangEn: "Alert",
	},
}

var i18nDescMap = map[string]map[string]string{
	"cpu_overload": {
		common.LangZh: "系统CPU占用率过高",
		common.LangEn: "System CPU usage too high",
	},
	"cpu_exceed": {
		common.LangZh: "CPU占用率超过%.1f%%",
		common.LangEn: "CPU usage exceeds %.1f%%",
	},
	"mem_overload": {
		common.LangZh: "系统MEM占用率过高",
		common.LangEn: "System memory usage too high",
	},
	"mem_exceed": {
		common.LangZh: "MEM占用率超过%.1f%%",
		common.LangEn: "Memory usage exceeds %.1f%%",
	},
	"disk_overload": {
		common.LangZh: "系统Disk占用率过高",
		common.LangEn: "System disk usage too high",
	},
	"disk_exceed": {
		common.LangZh: "Disk占用率超过%.1f%%",
		common.LangEn: "Disk usage exceeds %.1f%%",
	},
	"es_disk_overload": {
		common.LangZh: "系统ES组件磁盘占用率过高",
		common.LangEn: "Elasticsearch disk usage too high",
	},
	"es_disk_exceed": {
		common.LangZh: "ES组件磁盘占用率超过%.1f%%",
		common.LangEn: "Elasticsearch disk usage exceeds %.1f%%",
	},
	"es_cpu_overload": {
		common.LangZh: "系统ES组件CPU占用率过高",
		common.LangEn: "Elasticsearch CPU usage too high",
	},
	"es_cpu_exceed": {
		common.LangZh: "ES组件CPU占用率超过%1.f%%",
		common.LangEn: "Elasticsearch CPU usage exceeds %1.f%%",
	},
	"sensor_status_abnormal": {
		common.LangZh: "传感器状态异常",
		common.LangEn: "Sensor status abnormal",
	},
	"sensor_time_abnormal": {
		common.LangZh: "传感器时间异常",
		common.LangEn: "Sensor time abnormal",
	},
	"sensor_log_not_collected": {
		common.LangZh: "传感器日志未采集",
		common.LangEn: "Sensor logs not collected",
	},
	"sensor_log_abnormal": {
		common.LangZh: "传感器日志采集状态异常",
		common.LangEn: "Sensor log collection abnormal",
	},
	"sensor_log_collection_abnormal": {
		common.LangZh: "传感器日志采集异常",
		common.LangEn: "Sensor log collection abnormal",
	},
	"sensor_traffic_not_collected": {
		common.LangZh: "传感器流量未采集",
		common.LangEn: "Sensor traffic not collected",
	},
	"sensor_traffic_abnormal": {
		common.LangZh: "传感器流量采集状态异常",
		common.LangEn: "Sensor traffic collection abnormal",
	},
	"domain_status_abnormal": {
		common.LangZh: "域控制器状态异常",
		common.LangEn: "Domain controller status abnormal",
	},
	"domain_status_abnormal_desc": {
		common.LangZh: "域控服务器%s状态异常，最后在线时间为%s。",
		common.LangEn: "Domain controller %s status abnormal, last online time: %s.",
	},
	"ldap_connect_failed": {
		common.LangZh: "LDAP连接失败",
		common.LangEn: "LDAP connection failed",
	},
	"get_domain_dc_list_failed": {
		common.LangZh: "获取域DC列表失败",
		common.LangEn: "Failed to get domain DC list",
	},
	"invalid_username_or_password": {
		common.LangZh: "用户名或密码不正确",
		common.LangEn: "Invalid username or password",
	},
	"ldap_address_error": {
		common.LangZh: "ldap地址错误",
		common.LangEn: "LDAP address error",
	},
	"connection_timeout_check_dns": {
		common.LangZh: "连接超时，请检查DNS地址是否正确",
		common.LangEn: "Connection timeout, please check if DNS address is correct",
	},
	"unknown_error": {
		common.LangZh: "未知的错误:%v",
		common.LangEn: "Unknown error: %v",
	},
	// Email notification labels - Alert
	"email_threat_name": {
		common.LangZh: "威胁名称",
		common.LangEn: "Threat Name",
	},
	"email_threat_level": {
		common.LangZh: "威胁等级",
		common.LangEn: "Threat Level",
	},
	"email_threat_type": {
		common.LangZh: "威胁类型",
		common.LangEn: "Threat Type",
	},
	"email_affected_dc": {
		common.LangZh: "影响域控",
		common.LangEn: "Affected DC",
	},
	"email_threat_details": {
		common.LangZh: "威胁详情",
		common.LangEn: "Threat Details",
	},
	"email_start_time": {
		common.LangZh: "发生时间",
		common.LangEn: "Start Time",
	},
	"email_end_time": {
		common.LangZh: "结束时间",
		common.LangEn: "End Time",
	},
	// Email notification labels - Baseline
	"email_baseline_name": {
		common.LangZh: "基线名称",
		common.LangEn: "Baseline Name",
	},
	"email_baseline_type": {
		common.LangZh: "基线类型",
		common.LangEn: "Baseline Type",
	},
	"email_baseline_subtype": {
		common.LangZh: "基线子类型",
		common.LangEn: "Baseline Subtype",
	},
	"email_risk_level": {
		common.LangZh: "风险等级",
		common.LangEn: "Risk Level",
	},
	"email_risk_details": {
		common.LangZh: "风险详情",
		common.LangEn: "Risk Details",
	},
	"email_detect_time": {
		common.LangZh: "检测时间",
		common.LangEn: "Detection Time",
	},
	// Email notification labels - Vulnerability
	"email_vuln_name": {
		common.LangZh: "漏洞名称",
		common.LangEn: "Vulnerability Name",
	},
	"email_vuln_type": {
		common.LangZh: "漏洞类型",
		common.LangEn: "Vulnerability Type",
	},
	"email_vuln_details": {
		common.LangZh: "漏洞详情",
		common.LangEn: "Vulnerability Details",
	},
	// Email notification labels - System
	"email_msg_type": {
		common.LangZh: "消息类型",
		common.LangEn: "Message Type",
	},
	"email_component_type": {
		common.LangZh: "组件类型",
		common.LangEn: "Component Type",
	},
	"email_alert_details": {
		common.LangZh: "告警详情",
		common.LangEn: "Alert Details",
	},
	// Email template labels
	"email_title_suffix": {
		common.LangZh: "通知",
		common.LangEn: "Notification",
	},
	"email_platform_name": {
		common.LangZh: "Adaegis安全平台",
		common.LangEn: "Adaegis Platform",
	},
	"email_details_label": {
		common.LangZh: "详情",
		common.LangEn: "Details",
	},
	"email_footer": {
		common.LangZh: "更多历史消息请前往消息中心页面查看。",
		common.LangEn: "For more historical messages, please visit the Message Center.",
	},
	// Report export - Alert Event
	"report_sheet_alert_event": {
		common.LangZh: "告警事件",
		common.LangEn: "Alert Events",
	},
	"report_threat_name": {
		common.LangZh: "威胁名称",
		common.LangEn: "Threat Name",
	},
	"report_threat_desc": {
		common.LangZh: "威胁描述",
		common.LangEn: "Threat Description",
	},
	"report_dc_location": {
		common.LangZh: "所在域控",
		common.LangEn: "Domain Controller",
	},
	"report_attck_id": {
		common.LangZh: "Att&ck ID",
		common.LangEn: "ATT&CK ID",
	},
	"report_risk_level": {
		common.LangZh: "风险等级",
		common.LangEn: "Risk Level",
	},
	"report_rule_confidence": {
		common.LangZh: "规则置信度",
		common.LangEn: "Rule Confidence",
	},
	"report_tags": {
		common.LangZh: "标签",
		common.LangEn: "Tags",
	},
	"report_key_fields": {
		common.LangZh: "关键字段",
		common.LangEn: "Key Fields",
	},
	"report_related_activity_id": {
		common.LangZh: "关联行为ID",
		common.LangEn: "Related Activity ID",
	},
	"report_start_time": {
		common.LangZh: "开始时间",
		common.LangEn: "Start Time",
	},
	"report_end_time": {
		common.LangZh: "结束时间",
		common.LangEn: "End Time",
	},
	"report_duration": {
		common.LangZh: "持续时间",
		common.LangEn: "Duration",
	},
	"report_detect_time": {
		common.LangZh: "检测时间",
		common.LangEn: "Detection Time",
	},
	// Report export - Alert Activity
	"report_sheet_alert_activity": {
		common.LangZh: "行为侦测事件",
		common.LangEn: "Activity Detection Events",
	},
	"report_raw_log": {
		common.LangZh: "原始日志",
		common.LangEn: "Raw Log",
	},
	// Report export - Baseline
	"report_sheet_baseline": {
		common.LangZh: "基线事件",
		common.LangEn: "Baseline Events",
	},
	"report_baseline_name": {
		common.LangZh: "基线名称",
		common.LangEn: "Baseline Name",
	},
	"report_display_name": {
		common.LangZh: "显示名称",
		common.LangEn: "Display Name",
	},
	"report_domain": {
		common.LangZh: "所在域",
		common.LangEn: "Domain",
	},
	"report_baseline_type": {
		common.LangZh: "基线类型",
		common.LangEn: "Baseline Type",
	},
	"report_risk_score": {
		common.LangZh: "风险分值",
		common.LangEn: "Risk Score",
	},
	"report_detect_result": {
		common.LangZh: "检测结果",
		common.LangEn: "Detection Result",
	},
	"report_instance_count": {
		common.LangZh: "检测实例数",
		common.LangEn: "Instance Count",
	},
	"report_update_time": {
		common.LangZh: "更新时间",
		common.LangEn: "Update Time",
	},
	"report_description": {
		common.LangZh: "描述",
		common.LangEn: "Description",
	},
	"report_verify_desc": {
		common.LangZh: "验证说明",
		common.LangEn: "Verification",
	},
	"report_suggestion": {
		common.LangZh: "修复建议",
		common.LangEn: "Remediation",
	},
	// Report export - Vulnerability
	"report_sheet_leak": {
		common.LangZh: "漏洞事件",
		common.LangEn: "Vulnerability Events",
	},
	"report_vuln_name": {
		common.LangZh: "漏洞名称",
		common.LangEn: "Vulnerability Name",
	},
	"report_dc_name": {
		common.LangZh: "域控制器",
		common.LangEn: "Domain Controller",
	},
	"report_vuln_type": {
		common.LangZh: "漏洞类型",
		common.LangEn: "Vulnerability Type",
	},
	// Report export - Weak Password
	"report_sheet_weakpwd": {
		common.LangZh: "弱口令事件",
		common.LangEn: "Weak Password Events",
	},
	"report_username": {
		common.LangZh: "用户名",
		common.LangEn: "Username",
	},
	"report_password": {
		common.LangZh: "密码",
		common.LangEn: "Password",
	},
	"report_pwd_expire_time": {
		common.LangZh: "密码过期时间",
		common.LangEn: "Password Expiration",
	},
	"report_pwd_update_time": {
		common.LangZh: "密码修改时间",
		common.LangEn: "Password Modified",
	},
	"report_user_locked": {
		common.LangZh: "用户锁定状态",
		common.LangEn: "Locked Status",
	},
	// Report export - Audit
	"report_sheet_audit": {
		common.LangZh: "日志审计",
		common.LangEn: "Audit Logs",
	},
	"report_login_user": {
		common.LangZh: "登录用户",
		common.LangEn: "Login User",
	},
	"report_login_ip": {
		common.LangZh: "登录IP",
		common.LangEn: "Login IP",
	},
	"report_audit_event": {
		common.LangZh: "审计事件",
		common.LangEn: "Audit Event",
	},
	"report_event_args": {
		common.LangZh: "事件属性",
		common.LangEn: "Event Args",
	},
	"report_event_result": {
		common.LangZh: "事件结果",
		common.LangEn: "Event Result",
	},
	"report_audit_time": {
		common.LangZh: "审计时间",
		common.LangEn: "Audit Time",
	},
}

func getNotifyMsgTypeDesc(msgType, lang string) string {
	if m, ok := notifyMsgTypeDescMap[msgType]; ok {
		if desc, ok := m[lang]; ok {
			return desc
		}
		// fallback to Chinese
		return m[common.LangZh]
	}
	return msgType
}

func getI18n(key, lang string) string {
	if m, ok := i18nDescMap[key]; ok {
		if desc, ok := m[lang]; ok {
			return desc
		}
		// fallback to Chinese
		return m[common.LangZh]
	}
	return key
}
