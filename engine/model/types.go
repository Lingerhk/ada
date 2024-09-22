package model

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

// AlertActivityESDB 告警行为 索引(该表如有变动需同步到backend/model/tables.go:AlertActivityESDB)
type AlertActivityESDB struct {
	ID         primitive.ObjectID `bson:"_id,omitempty" json:"activity_id"` // ID (AlertActivity.ID)
	Title      string             `bson:"title" json:"title"`               // 告警标题(规则名称,即:RuleInfo.Name)
	Desc       string             `bson:"desc" json:"desc"`                 // 告警描述(事件详细描述,即:RuleInfo.EventTmpl格式化)
	RuleId     string             `bson:"rule_id" json:"rule_id"`           // sigma rule_id
	UniqueId   string             `bson:"unique_id" json:"unique_id"`       // UniqueId, 通过src_ip, username，dcHostname进行hash，通过此ID关联activity到同一事件
	AttCkId    string             `bson:"attck_id" json:"attck_id"`         // 规则ATT&CK Id,即:RuleTags[0])
	Level      int32              `bson:"level" json:"level"`               // 风险等级, 1:info, low:2, medium:3, high:4
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

// AlertEventESDB 告警行为 索引(该表如有变动需同步到backend/model/tables.go:AlertEventESDB)
type AlertEventESDB struct {
	ID          primitive.ObjectID `bson:"_id,omitempty" json:"event_id"`    // ID (AlertEvent.ID)
	Title       string             `bson:"title" json:"title"`               // 告警标题(规则名称,即:RuleInfo.Name)
	Desc        string             `bson:"desc" json:"desc"`                 // 告警描述(事件详细描述,即:RuleInfo.EventTmpl格式化)
	FlowId      string             `bson:"flow_id" json:"flow_id"`           // sigma flow_id
	UniqueId    string             `bson:"unique_id" json:"unique_id"`       // UniqueId, 通过src_ip, username，dcHostname进行hash，通过此ID关联activity到同一事件
	AttCkId     string             `bson:"attck_id" json:"attck_id"`         // 规则ATT&CK Id,即:RuleTags[0])
	Level       int32              `bson:"level" json:"level"`               // 风险等级, low:2, medium:3, high:4
	Status      string             `bson:"status" json:"status"`             // 规则状态,由sigma status同步过来
	EventStatus int32              `bson:"event_status" json:"event_status"` // 事件状态, 0:未处理, 1:已处理 2:已加白 3:已阻断
	Tags        []string           `bson:"tags" json:"tags"`                 // sigma rule tags
	DcHostname  string             `bson:"dc_hostname" json:"dc_hostname"`   // DC hostname
	ActivityIds []string           `bson:"activity_ids" json:"activity_ids"` // 关联行为日志(多条)
	Result      string             `bson:"result" json:"result"`             // 攻击结果(默认为-)
	Remark      string             `bson:"remark" json:"remark"`             // 备注说明（portal侧更新，默认为空）
	FieldData   map[string]string  `bson:"field_data" json:"field_data"`     // 攻击源信息
	CreateTm    time.Time          `bson:"create_tm" json:"create_tm"`       // 生成时间
	StartTs     int64              `bson:"start_ts" json:"start_ts"`         // 事件开始时间
	EndTs       int64              `bson:"end_ts" json:"end_ts"`             // 事件结束时间
}

func (a *AlertEventESDB) CollectName() string {
	return "tb_alert_event"
}
