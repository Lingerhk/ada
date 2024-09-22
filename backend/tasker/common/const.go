package common

const (
	CronDomainSyncPeriod   = 60 * 30 // 同步域控制器状态，30分钟同步
	CronSystemSyncPeriod   = 60      // 系统状态等同步
	CronADLdapSyncPeriod   = 3600    // AD敏感用户&组&计算机同步
	CronThreatNotifyPeriod = 12      // 威胁告警/扫描告警通知，12s同步
	CronSystemNotifyPeriod = 180     // 系统状态检查的通知，180s同步
)
