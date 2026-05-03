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

	FlowInstancePrefixKey  = "ada:engine:instance"
	FlowActiveSetPrefixKey = "ada:engine:active" // SADD记录每个flow_id的活跃instance(zsetKey)

	EveLogQueueKey = "ada:evelog_queue" // same with task_server module
	PktLogQueueKey = "ada:pktlog_queue" // same with task_server module

	AlertActivityIndexKey = "ada-activity" // ES索引: 攻击活动表

	AlertActivityCachePrefix = "ada:engine:activity_cache"

	AlertNotifyQueueKey = "ada:server:notify_queue" // 告警Notify推送队列(taskworker进行notify)

	EngineReloadChannel = "ada:engine:reload" // Redis pub/sub channel for engine rule reload

	LdapSearchPubsubChan       = "ada:engine:ldap_search_channel" // Flow $v.ldap cache miss async lookup channel
	LdapSearchPendingPrefixKey = "ada:engine:ldap_search_pending" // SETNX throttle key for repeated LDAP miss requests
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

	LdapSearchCacheTTLSeconds = 60 // LDAP consumer should populate Redis lookup sets with at least this ttl
)
