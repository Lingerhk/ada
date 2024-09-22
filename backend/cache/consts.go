package cache

const (
	SysStatsInfoKey  = "ada:server:stats:info"   // hash
	SysStatsLoadKey  = "ada:server:stats:load"   // hash
	SysStatsCpuKey   = "ada:server:stats:cpu"    // hash
	SysStatsMemKey   = "ada:server:stats:mem"    // hash
	SysStatsNetRxKey = "ada:server:stats:net_rx" // hash
	SysStatsNetTxKey = "ada:server:stats:net_tx" // hash
	SysStatsCfgKey   = "ada:server:stats:cfg"    // hash 监控阈值配置
)

const (
	LdapSearchPubsubChan = "ada:engine:ldap_search_channel"

	AlertNotifyQueueKey = "ada:server:notify_queue" // 告警Notify推送队列(push:engine/scanner, pop:threat_notify)

	SensorCollectStatusKey = "ada:sensor:collect_stats" // hash sensor采集日志/流量的最后时间

	FlowFieldMapKey = "ada:engine:flow_field_map" // hash flow_id:fields (split by ",")

	FlowWhitelistPrefixKey = "ada:engine:flow_whitelist" // hash flow_id:whitelist_id:conditions (split by "|[AND]|"
)
