package model

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 用户表
type User struct {
	ID           int32     `bson:"_id,omitempty"` // ID，自增
	UserName     string    `bson:"username"`      // username
	Password     string    `bson:"password"`      // encrypted password
	PassStrength string    `bson:"pass_strength"` // 密码强度: high/middle/low
	Role         string    `bson:"role"`          // 用户角色: dev|ops|sec|mgr|guest
	Priv         int32     `bson:"priv"`          // 权限类别： 1:super 2:admin
	Mobile       string    `bson:"mobile"`        // 手机号
	Email        string    `bson:"email"`         // 邮箱
	Remark       string    `bson:"remark"`        // 备注
	Secret       string    `bson:"secret"`        // 验证密钥
	MfaStatus    string    `bson:"mfa_status"`    // 二次认证状态 开启enable 禁用disable
	Avatar       string    `bson:"avatar"`        // 头像
	PwdUpdateTm  time.Time `bson:"pwd_update_tm"` // 密码更新时间 add by xc
	RealName     string    `bson:"real_name"`     // 真实姓名
	Department   string    `bson:"department"`    // 部门
	Post         string    `bson:"post"`          // 岗位
	Address      string    `bson:"address"`       // 所在地址
	CreateTm     time.Time `bson:"create_tm"`     // 添加时间
}

func (a *User) CollectName() string {
	return "tb_user"
}

// 日志审计
type AuditLog struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"` // ID
	Username    string             `bson:"username"`      //登录用户
	ClientIp    string             `bson:"client_ip"`     //源ip
	Event       string             `bson:"event"`         //事件
	EventArgs   string             `bson:"event_args"`    //事件参数
	EventResult string             `bson:"event_result"`  //事件结果 //成功 失败
	CreateTm    time.Time          `bson:"create_tm"`     // 添加时间
	Status      int32              `bson:"status"`        // 数据状态 1删除 0正常
}

func (a *AuditLog) CollectName() string {
	return "tb_audit_log"
}

// Domain配置表
type DCList struct {
	HostName     string    `bson:"hostname"`       // 域控DC主机名
	Platform     string    `bson:"platform"`       // 操作系统
	Version      string    `bson:"version"`        // 域控版本
	IPList       []string  `bson:"ip_list"`        // IP列表
	Timeout      string    `bson:"timeout"`        // 网络延迟，ping测试结果
	Status       string    `bson:"status"`         // run|stop|init|error
	HasSensor    bool      `bson:"has_sensor"`     // 是否安装sensor
	IsMaster     bool      `bson:"is_master"`      // DC服务器主节点
	FsmoRole     string    `bson:"fsmo_role"`      // DC服务器的角色(fsmo-roles)
	ErrMsg       string    `bson:"err_msg"`        // 错误信息
	LastOnlineTm time.Time `bson:"last_online_tm"` // 最后检测时间
}

type Domain struct {
	ID         primitive.ObjectID `bson:"_id,omitempty"` // ID
	Name       string             `bson:"name"`          // 域名
	DCHostName string             `bson:"dc_hostname"`   // 域控DC主机名
	Status     string             `bson:"status"`        // run|stop|init|error
	LdapConf   map[string]string  `bson:"ldap_conf"`     // ldap配置
	DCList     []DCList           `bson:"dc_list"`       // DC列表
	CreateTm   time.Time          `bson:"create_tm"`     // 添加时间
	ErrMsg     string             `bson:"err_msg"`       // 错误信息
}

func (a *Domain) CollectName() string {
	return "tb_domain"
}

// 系统信息表
type SystemInfo struct {
	ID             primitive.ObjectID `bson:"_id,omitempty"`   // ID
	SystemIP       string             `bson:"system_ip"`       // 系统IP
	SystemName     string             `bson:"system_name"`     // 系统名称
	SystemIcon     string             `bson:"system_icon"`     // 系统Logo
	SystemVersion  string             `bson:"system_version"`  // 系统版本
	UpgradeUrl     string             `bson:"upgrade_url"`     // 新版本检测
	NtpAddress     string             `bson:"ntp_address"`     // NTP服务器地址
	SystemLanguage string             `bson:"system_language"` // 系统语言(EN/ZH)
	StatsCfg       map[string]string  `bson:"stats_cfg"`       // 系统状态监控配置
	CreateTm       time.Time          `bson:"create_tm"`       // 系统安装时间
	UpgradeTm      time.Time          `bson:"upgrade_tm"`      // 系统上次更新时间
}

func (a *SystemInfo) CollectName() string {
	return "tb_system_info"
}

// 消息列表
type Notify struct {
	ID        primitive.ObjectID `bson:"_id"`        // ID
	Title     string             `bson:"title"`      // 标题
	MsgType   string             `bson:"msg_type"`   // 消息 扫描Scanner 告警事件Alert 系统消息System
	EventType string             `bson:"event_type"` // 事件类型
	Desc      string             `bson:"desc"`       // 描述
	Params    map[string]string  `bson:"params"`     // 属性
	Status    int32              `bson:"status"`     // 状态，0为未读，1为已读
	CreateTm  time.Time          `bson:"create_tm"`  // 事件发生时间
}

func (n *Notify) CollectName() string {
	return "tb_notify"
}

// NotifyConf 通知模块配置
type NotifyConf struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"` // 主键ID
	ModuleName  string             `bson:"module_name"`   // alert,baseline,leak,system
	NotifyType  string             `bson:"notify_type"`   // syslog,webhook,email
	Endpoint    string             `bson:"endpoint"`      // 通知目标
	MetaData    map[string]string  `bson:"metadata"`      // 存储数据，如email配置，sender,port,sender_identity,server,alert_interval
	Remark      string             `bson:"remark"`        // 备注说明
	Enable      string             `bson:"enable"`        // 是否开启,默认开启 开启enable 关闭disable
	NotifyLevel []int32            `bson:"notify_level"`  // 需要告警的严重性限制 2,3,4,5
	NotifyRules []string           `bson:"notify_rules"`  // 需要通知的rules，对于alert为flow_id，对于baseline/leak是plugin str(_id)，对于system: cpu/mem/disk/domain/sensor
	UpdateTm    time.Time          `bson:"update_tm"`     // 修改时间
}

func (c *NotifyConf) CollectName() string {
	return "tb_notify_conf"
}

// Sensor 列表
type Sensor struct {
	ID string `bson:"_id,omitempty"`
	// Sensor信息
	IP         string `bson:"ip"` // 域控IP
	DCHostName string `bson:"dc_hostname"`
	Domain     string `bson:"domain"`
	Status     string `bson:"status"`     // Init|Running|Stopped|Error
	Version    string `bson:"version"`    // Sensor 版本
	PktStatus  string `bson:"pkt_status"` // Init|Running|Stopped|Error
	LogStatus  string `bson:"log_status"` // Init|Running|Stopped|Error
	Timestamp  string `bson:"timestamp"`  // 宿主机的当前时间戳(用作时间校正)
	Remark     string `bson:"remark"`     // 备注
	// Plugin信息
	PktPluginSwitch    string `bson:"pkt_plugin_switch"`    // 流量插件开关
	LogPluginSwitch    string `bson:"log_plugin_switch"`    // 日志插件开关
	RpcFwPluginSwitch  string `bson:"rpcfw_plugin_switch"`  // rpcfw插件开关
	LdapFwPluginSwitch string `bson:"ldapfw_plugin_switch"` // ldapfw插件开关
	PktPluginStatus    string `bson:"pkt_plugin_status"`    // 流量插件状态 Init|Running|Stopped|Error
	LogPluginStatus    string `bson:"log_plugin_status"`    // 日志插件状态 Init|Running|Stopped|Error
	RpcFwPluginStatus  string `bson:"rpcfw_plugin_status"`  // rpcfw插件状态 Init|Running|Stopped|Error
	LdapFwPluginStatus string `bson:"ldapfw_plugin_status"` // ldapfw插件状态 Init|Running|Stopped|Error
	RpcFwCpuUsed       string `bson:"rpcfw_cpu_used"`
	RpcFwMemUsed       string `bson:"rpcfw_mem_used"`
	LdapFwCpuUsed      string `bson:"ldapfw_cpu_used"`
	LdapFwMemUsed      string `bson:"ldapfw_mem_used"`
	SensorCpuUsed      string `bson:"sensor_cpu_used"` // Sensor CPU使用率
	SensorMemUsed      string `bson:"sensor_mem_used"` // Sensor 内存使用率
	// DC宿主机信息
	Platform     string            `bson:"platform"`       // DC 平台
	KernelVer    string            `bson:"kernel_version"` // DC内核版本
	MemTotal     string            `bson:"mem_total"`      // 内存大小(DC)
	CpuTotal     string            `bson:"cpu_total"`      // CPU核数
	NetIface     map[string]string `bson:"net_iface"`      // 主机上网口列表
	BindNetIface []string          `bson:"bind_net_iface"` // 接口名list： ["eth0", "eth1"]
	PktBpfFilter string            `bson:"pkt_bpf_filter"` // 流量插件BPF过滤规则
	LogEvtFilter string            `bson:"log_evt_filter"` // 日志插件Event字段过滤规则

	DcIntervalTm int64 `bson:"dc_interval_tm"` // 域控时间与服务器时间的差值(秒)
	// 资源限制&Sensor运行日志
	PerfLimit map[string]string   `bson:"perf_limit"` // 资源占用限制
	Events    []map[string]string `bson:"events"`     // 运行日志
	// 时间
	CreateTm      time.Time `bson:"create_tm"`       // 添加时间
	LastOnlineTm  time.Time `bson:"last_online_tm"`  // 最后在线时间
	LastCollectTm time.Time `bson:"last_collect_tm"` // 最后采集时间
}

func (a *Sensor) CollectName() string {
	return "tb_sensor"
}

// ScanPlugin 列表
type ScanPlugin struct {
	ID           int32             `bson:"_id,omitempty"`
	Name         string            `bson:"name"`
	Display      string            `bson:"display"`
	Version      string            `bson:"version"`
	Enable       int32             `bson:"enable"`
	Category     string            `bson:"category"`
	Type         string            `bson:"type"`
	Points       float64           `bson:"points"`
	SubType      string            `bson:"sub_type"`
	Level        int32             `bson:"risk_level"`
	MetaData     map[string]any    `bson:"meta_data"`
	MetaDataDesc map[string]string `bson:"meta_data_desc"`
	Desc         string            `bson:"desc"`
	VerifyDesc   string            `bson:"verify_desc"`
	Suggestion   string            `bson:"suggestion"`
	Reference    string            `bson:"reference"`
	Remark       string            `bson:"remark"`
	UpdateTm     int               `bson:"update_tm"`
}

func (a *ScanPlugin) CollectName() string {
	return "tb_scan_plugin"
}

// ScanTemplate 原来的扫描模板
type ScanTemplate struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	Name     string             `bson:"name"`
	Type     string             `bson:"type"`      // baseline|leak|weakpwd
	Plugins  []ScanPlugin       `bson:"plugins"`   //
	TmplType int32              `bson:"tmpl_type"` // 模板类型：1:默认, 2:自定义
	CreateTm time.Time          `bson:"create_tm"`
	UpdateTm time.Time          `bson:"update_tm"`
}

func (a *ScanTemplate) CollectName() string {
	return "tb_scan_template"
}

// ScanTasks 列表
type ScanTasks struct {
	ID            primitive.ObjectID `bson:"_id,omitempty"`
	Type          string             `bson:"type"`    // baseline|leak|weakpwd
	Status        string             `bson:"status"`  // PENDING|RUNNING|FINISH|FAILURE
	Trigger       string             `bson:"trigger"` // once|cycle
	SubTasksTotal int32              `bson:"subtasks_total"`
	SubTasksFin   int32              `bson:"subtasks_finish"`
	Domain        string             `bson:"domain"`
	TemplateId    string             `bson:"template_id"`
	ErrMsg        string             `bson:"error_msg"`
	CreateTm      time.Time          `bson:"create_tm"`
	UpdateTm      time.Time          `bson:"update_tm"`
}

func (a *ScanTasks) CollectName() string {
	return "tb_scan_tasks"
}

type PluginInfo struct {
	ID           int32             `bson:"_id,omitempty"`
	Name         string            `bson:"name"`
	Display      string            `bson:"display"`
	Version      string            `bson:"version"`
	Enable       int32             `bson:"enable"`
	Type         string            `bson:"type"`
	SubType      string            `bson:"sub_type"`
	Points       float64           `bson:"points"`
	Category     string            `bson:"category"`
	Desc         string            `bson:"desc"`
	VerifyDesc   string            `bson:"verify_desc"`
	Suggestion   string            `bson:"suggestion"`
	Reference    string            `bson:"reference"`
	Remark       string            `bson:"remark"`
	UpdateTm     int64             `bson:"update_tm"`
	RiskLevel    int32             `bson:"risk_level"`
	MetaData     map[string]any    `bson:"meta_data"`
	MetaDataDesc map[string]string `bson:"meta_data_desc"`
}

type SubTaskResult struct {
	Status int32          `bson:"status"` // 1|0|?
	Desc   string         `bson:"desc"`
	Data   map[string]any `bson:"data"` // baseline: {"instance_list": [{"k":"v"}]}; leak: {}; weakpwd: {"users": [obj1,...], "domain":xxx}
	ErrMsg string         `bson:"error"`
	Plugin PluginInfo     `bson:"plugin"`
}

// ScanSubTasks 列表
type ScanSubTasks struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"`
	TaskID   string             `bson:"task_id"`
	GroupID  string             `bson:"group_id"`
	Status   string             `bson:"status"`
	Result   SubTaskResult      `bson:"result"`
	Params   map[string]any     `bson:"params"`
	ErrMsg   string             `bson:"error_msg"`
	CreateTm time.Time          `bson:"create_tm"`
	UpdateTm time.Time          `bson:"update_tm"`
}

func (a *ScanSubTasks) CollectName() string {
	return "tb_scan_subtasks"
}

// ScanConf 列表
type ScanConf struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Name      string             `bson:"name"`
	TaskFun   string             `bson:"task_fun"` // ScannerBaselineTask|ScannerLeakTask|ScannerWeakPwdTask
	Type      string             `bson:"type"`     // baseline|leak|weakpwd
	IsEnable  bool               `bson:"is_enable"`
	CycleType int32              `bson:"cycle_type"` // 1是day，2是week，3是month
	RunTime   string             `bson:"run_time"`
	Rate      int32              `bson:"rate"`
	Desc      string             `bson:"desc"`
	Plans     map[string]string  `bson:"plans"` // domain: template_id
	CreateTm  time.Time          `bson:"create_tm"`
	UpdateTm  time.Time          `bson:"update_tm"`
}

func (a *ScanConf) CollectName() string {
	return "tb_scan_conf"
}

// Sigma规则 描述表
type AttackFlow struct {
	Desc    string              `bson:"desc"`   // 描述
	Fields  []map[string]string `bson:"fields"` // obj(支持ip/user/computer/dc), key, value. eg: {"obj":"ip","key":"$1.TargetUsername","value":"192.168.2.3"}
	Relates []string            `bson:"relates"`
}

type AlertDetection struct {
	EventType  string   `bson:"event_type" yaml:"event_type"`   // 事件类型
	WinSize    int64    `bson:"win_size" yaml:"win_size"`       // 窗口大小
	Sorted     bool     `bson:"sorted" yaml:"sorted"`           // 是否排序
	SigmaRules []string `bson:"sigma_rules" yaml:"sigma_rules"` // 关联sigma规则
	MatchBy    string   `bson:"match_by" yaml:"match_by"`       // 匹配条件
}

type AlertRule struct {
	ID          string         `bson:"_id,omitempty"` // id
	Title       string         `bson:"title"`         // 事件标题
	Description string         `bson:"description"`   // 事件描述
	Enable      bool           `bson:"enable"`        // 启动状态
	Level       int32          `bson:"level"`         // 威胁等级 5:critical, 4:high, 3:medium, 2:low, 1:info
	Status      string         `bson:"status"`        // 规则状态: test|experimental|stable|deprecated
	Tags        []string       `bson:"tags"`          // 规则标签
	Logsource   string         `bson:"logsource"`     // 日志来源
	Detection   AlertDetection `bson:"detection"`     // 检测配置
	Type        string         `bson:"type"`          // 规则分类
	References  []string       `bson:"references"`    // 规则参考
	Suggestion  string         `bson:"suggestion"`    // 修复建议
	Author      string         `bson:"author"`        // 作者
	AutoBlock   bool           `bson:"auto_block"`    // 是否自动阻断
	AttackFlow  AttackFlow     `bson:"attack_flow"`   // 攻击描述图谱
	CreateTm    time.Time      `bson:"create_tm"`     // 创建时间
	UpdateTm    time.Time      `bson:"update_tm"`     // 修改时间
}

func (r *AlertRule) CollectName() string {
	return "tb_alert_rule"
}

// ActivityDetection stores the dynamic detection field from Sigma rules.
// The structure varies by rule type:
//
// For winlog/pktlog rules (single event matching):
//   - Contains dynamic selectors (selection1, filter1, etc.) as map keys
//   - Contains "condition" field with boolean expression
//     Example: {"selection1": {...}, "filter1": {...}, "condition": "selection1 and not filter1"}
//
// For flow rules (event correlation):
//   - event_type: count | multi_eve | multi_pkt
//   - win_size: time window like "30s", "3h"
//   - sorted: boolean for ordered matching
//   - selection: {sigma_id: [...], match_by: "..."}
//     Example: {"event_type": "count", "win_size": "30s", "selection": {...}}
type ActivityDetection map[string]any

type AlertActivityRule struct {
	ID           string            `bson:"_id,omitempty"`
	Title        string            `bson:"title"`         // 规则标题
	Description  string            `bson:"description"`   // 规则描述
	Level        int32             `bson:"level"`         // 风险等级,5:critical, 4:high, 3:medium, 2:low, 1:info
	Status       string            `bson:"status"`        // 状态, test|experimental|stable|deprecated
	Tags         []string          `bson:"tags"`          // 标签(MITRE ATT&CK等)
	Logsource    string            `bson:"logsource"`     // 日志来源
	References   []string          `bson:"references"`    // 规则参考
	Detection    ActivityDetection `bson:"detection"`     // 检测配置(动态结构)
	RdxKey       string            `bson:"rdx_key"`       // 规则缓存key
	Fields       []string          `bson:"fields"`        // 提取字段
	UniqueFields []string          `bson:"unique_fields"` // 唯一字段hash
	Author       string            `bson:"author"`        // 作者
	CreateTm     time.Time         `bson:"create_tm"`     // 生成时间
	UpdateTm     time.Time         `bson:"update_tm"`     // 修改时间
}

func (a *AlertActivityRule) CollectName() string {
	return "tb_activity_rule"
}

// AlertActivityESDB 告警行为表(该表必须保持和engine/core/types.go:AlertActivityESDB一致)
type AlertActivityESDB struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"activity_id"` // ID (AlertActivity.ID)
	Title      string             `bson:"title" json:"title"`               // 告警标题(规则名称,即:RuleInfo.Name)
	Desc       string             `bson:"desc" json:"desc"`                 // 告警描述(事件详细描述,即:RuleInfo.EventTmpl格式化)
	RuleId     string             `bson:"rule_id" json:"rule_id"`           // sigma rule_id
	UniqueId   string             `bson:"unique_id" json:"unique_id"`       // UniqueId, 通过src_ip, username，dcHostname进行hash，通过此ID关联activity到同一事件
	AttCkId    string             `bson:"attck_id" json:"attck_id"`         // 规则ATT&CK Id,即:RuleTags[0])
	Level      int32              `bson:"level" json:"level"`               // 风险等级, high,medium,low,info
	Status     string             `bson:"status" json:"status"`             // 状态,由sigma status同步过来
	Tags       []string           `bson:"tags" json:"tags"`                 // sigma rule tags
	DcHostname string             `bson:"dc_hostname" json:"dc_hostname"`   // DC hostname
	RawLog     string             `bson:"raw_log" json:"raw_log"`           // 关联原始日志
	Result     string             `bson:"result" json:"result"`             // 攻击结果
	FieldData  map[string]string  `bson:"field_data" json:"field_data"`     // 攻击源信息
	CreateTm   time.Time          `bson:"create_tm" json:"create_tm"`       // 生成时间
	TimeStamp  int64              `bson:"timestamp" json:"@timestamp"`      // 文档插入时间
}

func (a *AlertActivityESDB) CollectName() string {
	return "tb_alert_activity"
}

// AlertEventESDB 告警行为 索引(该表必须保持和engine/core/types.go::AlertEventESDB一致)
type AlertEventESDB struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"event_id"`    // ID (AlertEvent.ID)
	Title       string             `bson:"title" json:"title"`               // 告警标题(规则名称,即:RuleInfo.Name)
	Desc        string             `bson:"desc" json:"desc"`                 // 告警描述(事件详细描述,即:RuleInfo.EventTmpl格式化)
	FlowId      string             `bson:"flow_id" json:"flow_id"`           // sigma flow_id
	UniqueId    string             `bson:"unique_id" json:"unique_id"`       // UniqueId, 通过src_ip, username，dcHostname进行hash，通过此ID关联activity到同一事件
	AttCkId     string             `bson:"attck_id" json:"attck_id"`         // 规则ATT&CK Id,即:RuleTags[0])
	Level       int32              `bson:"level" json:"level"`               // 风险等级, high,middle,low
	Status      string             `bson:"status" json:"status"`             // 规则状态,由sigma status同步过来
	EventStatus int32              `bson:"event_status" json:"event_status"` // 事件状态, 0:未处理, 1:已处理 2:已加白 3:已阻断
	Tags        []string           `bson:"tags" json:"tags"`                 // sigma rule tags
	DcHostname  string             `bson:"dc_hostname" json:"dc_hostname"`   // DC hostname
	ActivityIds []string           `bson:"activity_ids" json:"activity_ids"` // 关联行为日志(多条)
	Result      string             `bson:"result" json:"result"`             // 攻击结果
	Remark      string             `bson:"remark" json:"remark"`             // 备注说明（portal侧更新，默认为空）
	FieldData   map[string]string  `bson:"field_data" json:"field_data"`     // 攻击源信息
	CreateTm    time.Time          `bson:"create_tm" json:"create_tm"`       // 生成时间
	StartTs     int64              `bson:"start_ts" json:"start_ts"`         // 事件开始时间
	EndTs       int64              `bson:"end_ts" json:"end_ts"`             // 事件结束时间
}

func (a *AlertEventESDB) CollectName() string {
	return "tb_alert_event"
}

// AlertWhitelist 告警规则白名单
type AlertWhitelist struct {
	ID       primitive.ObjectID  `bson:"_id,omitempty"` // ID (AlertEvent.ID)
	RuleId   string              `bson:"rule_id"`       // 规则ID
	RuleName string              `bson:"rule_name"`     // 规则名称
	RuleType string              `bson:"rule_type"`     // 告警类型 tag[0]
	RuleInfo []map[string]string `bson:"rule_info"`     // 规则内容
	Origin   int32               `bson:"origin"`        // 添加来源，手动添加: 1 自动添加:2
	Domain   string              `bson:"domain"`        // Domain
	Remark   string              `bson:"remark"`        // 备注
	CreateTm time.Time           `bson:"create_tm"`     // 创建时间
	UpdateTm time.Time           `bson:"update_tm"`     // 修改时间
}

func (a *AlertWhitelist) CollectName() string {
	return "tb_alert_whitelist"
}

// AlertBlock 威胁阻断表
type AlertBlock struct {
	ID        primitive.ObjectID  `bson:"_id,omitempty"` // ID
	Name      string              `bson:"name"`          // 阻断名称
	Domain    string              `bson:"domain"`        // Domain
	Origin    int32               `bson:"origin"`        // 来源，分为自动和手动，0为自动，1为手动添加
	UserBlock bool                `bson:"user_block"`    // 用户阻断
	IpBlock   bool                `bson:"ip_block"`      // IP阻断
	UserList  []string            `bson:"user_list"`     // 用户列表
	IpList    []string            `bson:"ip_list"`       // IP列表
	Result    []map[string]string `bson:"result"`        // 阻断结果 [{"dc_hostname":"dc01.xx","ip_status":"ok","user_status":"err","time":"xx"},{}]
	Remark    string              `bson:"remark"`        // 备注
	CreateTm  time.Time           `bson:"create_tm"`     // 添加时间
	UpdateTm  time.Time           `bson:"update_tm"`     // 修改时间
}

func (a *AlertBlock) CollectName() string {
	return "tb_alert_block"
}

// SensitiveEntry 敏感user/group/computer条目
type SensitiveEntry struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"` // ID
	Domain   string             `bson:"domain"`
	Type     string             `bson:"type"`      // user|group|computer|honeyuser
	Content  map[string]string  `bson:"content"`   // 条目内容，如果是敏感组则包括guid,sid,name字段
	Origin   int32              `bson:"origin"`    // 来源，分为自动和手动，0为ldap自动同步，1为页面手动添加
	CreateTm time.Time          `bson:"create_tm"` // 添加时间
	UpdateTm time.Time          `bson:"update_tm"` // 修改时间
}

func (a *SensitiveEntry) CollectName() string {
	return "tb_sensitive_entry"
}

// AssetUser 资产表user
type AssetUser struct {
	ID                 primitive.ObjectID `bson:"_id,omitempty"` // ID
	SAMAccountName     string             `bson:"sAMAccountName"`
	IsDelete           bool               `bson:"isDelete"`
	Dn                 string             `bson:"dn"`
	Name               string             `bson:"name"`
	ObjectSid          string             `bson:"objectSid"`
	Domain             string             `bson:"domain"`
	LastLogon          int64              `bson:"lastLogon"`
	PwdLastSet         int64              `bson:"pwdLastSet"`
	Email              string             `bson:"email"`
	PrimaryGroupID     int64              `bson:"primaryGroupID"`
	ObjectGUID         string             `bson:"objectGUID"`
	UserAccountControl int64              `bson:"userAccountControl"`
	SyncTm             int64              `bson:"syncTm"`
}

func (a *AssetUser) CollectName() string {
	return "tb_asset_user"
}

// AssetGroup 资产表group
type AssetGroup struct {
	ID                   primitive.ObjectID `bson:"_id,omitempty"` // ID
	SAMAccountName       string             `bson:"sAMAccountName"`
	IsDelete             bool               `bson:"isDelete"`
	sAMAccountType       int64              `bson:"sAMAccountType"`
	Dn                   string             `bson:"dn"`
	Name                 string             `bson:"name"`
	ObjectSid            string             `bson:"objectSid"`
	Domain               string             `bson:"domain"`
	AdminCount           int64              `bson:"adminCount"`
	ObjectGUID           string             `bson:"objectGUID"`
	ObjectCategory       string             `bson:"objectCategory"`
	nTSecurityDescriptor any                `bson:"nTSecurityDescriptor"`
	WhenCreated          int64              `bson:"whenCreated"`
	SyncTm               int64              `bson:"syncTm"`
}

func (a *AssetGroup) CollectName() string {
	return "tb_asset_group"
}

// AssetComputer 资产表computer
type AssetComputer struct {
	ID                     primitive.ObjectID `bson:"_id,omitempty"` // ID
	SAMAccountName         string             `bson:"sAMAccountName"`
	IsDelete               bool               `bson:"isDelete"`
	Dn                     string             `bson:"dn"`
	Name                   string             `bson:"name"`
	ObjectSid              string             `bson:"objectSid"`
	Domain                 string             `bson:"domain"`
	OperatingSystem        string             `bson:"operatingSystem"`
	OperatingSystemVersion string             `bson:"operatingSystemVersion"`
	DnsHostName            string             `bson:"dNSHostName"`
	ServicePrincipalName   []string           `bson:"servicePrincipalName"`
	CountryCode            int64              `bson:"countryCode"`
	ObjectGUID             string             `bson:"objectGUID"`
	IsCriticalSystemObject bool               `bson:"isCriticalSystemObject"`
	UserAccountControl     int64              `bson:"userAccountControl"`
	WhenCreated            int64              `bson:"whenCreated"`
	PrimaryGroupID         int64              `bson:"primaryGroupID"`
	LastLogonTimestamp     int64              `bson:"lastLogonTimestamp"`
	SyncTm                 int64              `bson:"syncTm"`
}

func (a *AssetComputer) CollectName() string {
	return "tb_asset_computer"
}

// ExportTask
type ExportTask struct {
	ID       primitive.ObjectID `bson:"_id,omitempty"` // 主键ID
	Name     string             `bson:"name"`          // 名称
	TaskID   string             `bson:"task_id"`       // (异步)任务ID
	Type     string             `bson:"type"`          // alert/baseline/leak/weakpwd/system/audit
	Params   map[string]string  `bson:"params"`        // 属性:{"domain":"A,B","start_tm":xxx,"end_tm":xxx}
	FileType string             `bson:"file_type"`     // xlsx,pdf
	Status   string             `bson:"status"`        // padding,doing,finish,failed
	FilePath string             `bson:"file_path"`     // 文件存储位置
	ErrMsg   string             `bson:"err_msg"`       // 错误信息
	CreateTm time.Time          `bson:"create_tm"`     // 创建时间
	UpdateTm time.Time          `bson:"update_tm"`     // 每次更新状态的时间
}

func (c *ExportTask) CollectName() string {
	return "tb_export_task"
}

// SystemLogs represents system log for API responses
// Note: Time is stored as string (RFC3339 format) for JSON serialization
type SystemLogs struct {
	Time   string `bson:"time" json:"time"`
	Level  string `bson:"level" json:"level"`
	Module string `bson:"module" json:"module"`
	Msg    string `bson:"msg" json:"msg"`
	Func   string `bson:"func" json:"func"`
	File   string `bson:"file" json:"file"`
}

func (s *SystemLogs) CollectName() string {
	return "tb_system_logs"
}
