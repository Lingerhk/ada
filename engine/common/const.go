package common

const (
	RuleDir    = "/home/adadmin/rules"
	RuleWinLog = "winlog"
	RulePktLog = "pktlog"
	RuleFlow   = "flow"

	FlowRuleMapKey  = "ada:engine:flow_rule_map"
	FlowFieldMapKey = "ada:engine:flow_field_map"

	SensorCollectStatusKey = "ada:sensor:collect_stats" // 采集状态

	FlowWhitelistPrefixKey = "ada:engine:flow_whitelist"

	FlowInstancePrefixKey = "ada:engine:instance"

	EveLogQueueKey = "ada:evelog_queue" // same with task_server module
	PktLogQueueKey = "ada:pktlog_queue" // same with task_server module

	AlertActivityIndexKey = "ada-activity" // ES索引: 攻击活动表

	AlertActivityCachePrefix = "ada:engine:activity_cache"

	AlertNotifyQueueKey = "ada:server:notify_queue" // 告警Notify推送队列(taskworker进行notify)

	EngineReloadChannel = "ada:engine:reload" // Redis pub/sub channel for engine rule reload
)

// flow规则支持的类型
const (
	EventTypeCount       = "count"
	EventTypeMultiEve    = "multi_eve"
	EventTypeMultiPkt    = "multi_pkt"
	EventTypeMultiEvePkt = "multi_eve_pkt"
)

// flow 配置
const (
	MaxFlowSelections = 16       // flow关联sigma的最大数量
	MaxFlowWinSize    = 6 * 3600 // flow最大窗口大小(6h)
)
