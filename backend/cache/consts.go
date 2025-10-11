package cache

const (
	SysStatsInfoKey  = "ada:server:stats:info"   // hash
	SysStatsLoadKey  = "ada:server:stats:load"   // list
	SysStatsCpuKey   = "ada:server:stats:cpu"    // list
	SysStatsMemKey   = "ada:server:stats:mem"    // list
	SysStatsNetRxKey = "ada:server:stats:net_rx" // list
	SysStatsNetTxKey = "ada:server:stats:net_tx" // list
	SysStatsCfgKey   = "ada:server:stats:cfg"    // hash 监控阈值配置

	SysStatsPktLogKey = "ada:server:stats:pktlog:%s" // 流量日志统计(domain)
	SysStatsWinLogKey = "ada:server:stats:winlog:%s" // 事件日志统计(domain)
)

const (
	LdapSearchPubsubChan = "ada:engine:ldap_search_channel"

	AlertNotifyQueueKey = "ada:server:notify_queue" // 告警Notify推送队列(push:engine/scanner, pop:threat_notify)

	SensorCollectStatusKey = "ada:sensor:collect_stats" // hash sensor采集日志/流量的最后时间

	FlowFieldMapKey = "ada:engine:flow_field_map" // hash flow_id:fields (split by ",")

	FlowWhitelistPrefixKey = "ada:engine:flow_whitelist" // hash flow_id:whitelist_id:conditions (split by "|[AND]|"

	EngineReloadChannel = "ada:engine:reload" // Redis pub/sub channel for engine rule reload
)
