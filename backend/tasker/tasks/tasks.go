package tasks

import (
	"ada/backend/tasker/worker"
	"github.com/RichardKnop/machinery/v2/tasks"
)

// 所有任务需在这里定义
const (
	DomainSyncName      = "domain_sync_task"
	ADLdapSyncName      = "ad_ldap_sync_task"
	SystemSyncName      = "system_sync_task"
	ScannerBaselineName = "scanner_baseline_task"
	ScannerLeakName     = "scanner_leak_task"
	ScannerWeakPwdName  = "scanner_weakpwd_task"
	ScannerRecheckName  = "scanner_recheck_task"
	ThreatNotifyName    = "threat_notify_task"
	SystemNotifyName    = "system_notify_task"

	ExportReportName = "export_report_task"
)

// 所有任务需在这里注册
func GetTaskMap(w *worker.Worker) map[string]any {
	return map[string]any{
		DomainSyncName:      w.DomainSyncTask,
		ADLdapSyncName:      w.ADLdapSyncTask,
		SystemSyncName:      w.SystemSyncTask,
		ScannerBaselineName: w.ScannerBaselineTask,
		ScannerLeakName:     w.ScannerLeakTask,
		ScannerWeakPwdName:  w.ScannerWeakPwdTask,
		ScannerRecheckName:  w.ScannerRecheckTask,
		ThreatNotifyName:    w.ThreatNotifyTask,
		SystemNotifyName:    w.SystemNotifyTask,
		ExportReportName:    w.ExportReportTask,
	}
}

// 域控制器状态同步(grpc task)
func TaskDomainSync() *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name:       DomainSyncName,
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// AD敏感用户&组&计算机同步(cron task)
func TaskADLdapSync() *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name:       ADLdapSyncName,
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskSystemSync clean sys log and internal items...(cron task)
func TaskSystemSync() *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name:       SystemSyncName,
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskScannerBaseline exec baseline scanning(grpc task)
func TaskScannerBaseline(dmTmplMap string) *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name: ScannerBaselineName,
		Args: []tasks.Arg{
			{
				Type:  "string",
				Value: dmTmplMap,
			},
		},
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskScannerLeak exec leak scanning(grpc task)
func TaskScannerLeak(dmTmplMap string) *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name: ScannerLeakName,
		Args: []tasks.Arg{
			{
				Type:  "string",
				Value: dmTmplMap,
			},
		},
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskScannerWeakPwd exec weak_pwd scanning(grpc task)
func TaskScannerWeakPwd(dmTmplMap string) *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name: ScannerWeakPwdName,
		Args: []tasks.Arg{
			{
				Type:  "string",
				Value: dmTmplMap,
			},
		},
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskScannerRecheck exec weak_pwd scanning(grpc task)
func TaskScannerRecheck(scanType, subTaskId string) *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name: ScannerRecheckName,
		Args: []tasks.Arg{
			{
				Type:  "string",
				Value: scanType,
			},
			{
				Type:  "string",
				Value: subTaskId,
			},
		},
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskThreatNotify notify threat events and scanrisk event(cron task)
func TaskThreatNotify() *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name:       ThreatNotifyName,
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskSystemNotify notify system status(cron task)
func TaskSystemNotify() *tasks.Signature {
	taskInstance := &tasks.Signature{
		Name:       SystemNotifyName,
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}

// TaskExportScanRisk export scan risk data(grpc task)
func TaskExportReport(taskUUid, typ, params string) *tasks.Signature {
	taskInstance := &tasks.Signature{
		UUID: taskUUid,
		Name: ExportReportName,
		Args: []tasks.Arg{
			{
				Type:  "string",
				Value: taskUUid,
			},
			{
				Type:  "string",
				Value: typ,
			},
			{
				Type:  "string",
				Value: params,
			},
		},
		RetryCount: 1, // If the task fails, retry it up to 1 times
	}
	return taskInstance
}
