package core

import (
	"ada/engine/common"
	"ada/engine/model"
	"ada/engine/sigma"
	"ada/infra/datamodels"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 并发执行
func (e *EngineWorker) sigmaRuleMatcher(ctx context.Context, channel, payload string) {
	var obj datamodels.Map
	if err := json.Unmarshal([]byte(payload), &obj); err != nil {
		logger.Errorf("json unmarshal err:%v", err)
		return
	}

	logger.Debugf("channel: %s message:%s", channel, payload)

	var ruleType string
	switch channel {
	case common.EveLogQueueKey:
		ruleType = common.RuleWinLog
	case common.PktLogQueueKey:
		ruleType = common.RulePktLog
	default:
		logger.Errorf("ingore invalid message from %s: %s", channel, payload)
		return
	}

	dcHostname, ok := obj.GetString("Hostname")
	if !ok {
		logger.Debugf("get Hostname from rawlog failed, will ignore this alert!!!")
		return
	}

	// 进行heartbeat心跳记录
	go e.heartbeat(ctx, ruleType, dcHostname)

	if e.preFilter(ctx, ruleType, obj) {
		logger.Debugf("pre-filter passed, will ignore this rawlog!!!")
		return
	}

	results, ok := e.ruleset[ruleType].EvalAll(obj)
	if ok && len(results) > 0 {
		logger.Debugf("found %d results(%s):%v", len(results), dcHostname, results)

		e.syncAlert(ctx, ruleType, payload, dcHostname, results)
	}
}

func (e *EngineWorker) heartbeat(ctx context.Context, ruleType, dcHostname string) {
	// 记录心跳信息
	ts := time.Now().Unix()
	if ts%10 == 0 {
		heartbeatKey := fmt.Sprintf("%s_%s", ruleType, dcHostname)
		err := e.redisCli.HSet(ctx, common.SensorCollectStatusKey, heartbeatKey, ts).Err()
		if err != nil {
			logger.Errorf("set heartbeat(dcHostname:%s, type:%s) err:%v", dcHostname, ruleType, err)
		}
	}
}

func (e *EngineWorker) preFilter(ctx context.Context, ruleType string, obj datamodels.Map) bool {
	// 日志预过滤，过滤掉不需要处理的日志 按照EventID 或者xxx
	_, ok := obj.GetNumber("EventID") // TODO: 这里仅winlog支持EventID过滤，后期将该能力迁移到agent端nxlog配置中
	if !ok {
		return false
	}
	//exist := e.redisCli.SIsMember(ctx, "ada:engine:filter_winlog", strconv.Itoa(int(eventId))).Val()
	//if exist {
	//	return true
	//}

	return false
}

func (e *EngineWorker) syncAlert(ctx context.Context, ruleType, rawLog, dcHostname string, results sigma.Results) {
	var alertByte []byte

	// 一个日志可能触发多条告警
	for _, result := range results {
		logger.Debugf("[+++++] found result: id:%s, title: %s, dcHostname:%s, unique_id:%s, fields:%#v", result.ID, result.Title, dcHostname, result.UniqueId, result.Fields)

		rule := e.ruleset[ruleType].GetRule(result.ID)
		if rule == nil {
			logger.Errorf("get rule by id %s failed, will ignore this alert!!!", result.ID)
			continue
		}

		// 判断是否为内置规则，如果是的话，还需要更新特殊cache: rdx_key
		// 内置规则不会产生告警，仅cache一些信息，以便其他规则匹配时使用
		if strings.HasPrefix(rule.ID, "winlog-0000-") || strings.HasPrefix(rule.ID, "pktlog-0000-") {
			if rule.RdxKey != "" && strings.HasPrefix(rule.RdxKey, "rule_cache") {
				e.cacheInternalActivity(ctx, result, rule)
				continue
			}
		}

		act := model.AlertActivityESDB{
			Title:      rule.Title,
			Desc:       rule.Description,
			RuleId:     result.ID,
			AttCkId:    rule.Tags[0],
			Level:      common.GetRiskLevel(rule.Level),
			Status:     rule.Status,
			Tags:       rule.Tags,
			DcHostname: dcHostname,
			RawLog:     rawLog,
			FieldData:  result.Fields,
			UniqueId:   result.UniqueId,
			CreateTm:   time.Now(),
			TimeStamp:  time.Now().UnixNano() / 1e6,
		}

		// 将告警存入mongodb
		mId, err := e.syncMongodb(act)
		if err != nil {
			logger.Errorf("sync alert to mongodb err:%v", err)
			continue
		}

		act.ID = mId
		if alertByte, err = json.Marshal(act); err != nil {
			logger.Errorf("json marshal alert es event err:%v", err)
			continue
		}

		// 将告警存入elasticsearch
		eId, err := e.syncElasticsearch(ctx, alertByte)
		if err != nil {
			logger.Errorf("sync alert to es err:%v", err)
			continue
		}

		// 将告警关联信息存入flow engine cache zset
		err = e.syncFlowEngine(ctx, eId, mId.Hex(), dcHostname, result, rule)
		if err != nil {
			logger.Errorf("sync alert to flow_engine err:%v", err)
			continue
		}
	}
}

func (e *EngineWorker) syncElasticsearch(ctx context.Context, alertBytes []byte) (string, error) {
	if e.esCli == nil {
		logger.Debugf("ES disabled, skip indexing")
		return "es_disabled", nil
	}

	// return the es document _id
	req := esapi.IndexRequest{
		Index:   common.AlertActivityIndexKey,
		Body:    bytes.NewReader(alertBytes),
		Refresh: "true",
	}

	res, err := req.Do(ctx, e.esCli)
	if err != nil {
		logger.Errorf("indexing err: %v", err)
		return "", err
	}
	defer res.Body.Close()
	if res.IsError() {
		logger.Errorf("indexing doc err:%s", res.Status())
		return "", err
	}

	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		logger.Errorf("Error parsing the response body: %v", err)
		return "", err
	}

	if _id, ok := r["_id"]; ok {
		return _id.(string), nil
	}

	return "", nil
}

func (e *EngineWorker) syncMongodb(act model.AlertActivityESDB) (primitive.ObjectID, error) {
	act.ID = primitive.NewObjectID()

	// 插入单条行为
	if err := e.mongoCli.Insert(act.CollectName(), act); err != nil {
		logger.Warnf("insert activity err:%v", err)
		return primitive.NilObjectID, err
	}

	return act.ID, nil
}

// cacheActivityMeta 将对应事件的概述信息cache到redis, ttl:6h
func (e *EngineWorker) cacheActivityMeta(ctx context.Context, eId, mId, dcHostname string, result sigma.Result, rule *sigma.Rule) (string, error) {
	eventInfo := make(map[string]interface{})
	eventInfo["mid"] = mId
	eventInfo["eid"] = eId
	eventInfo["sid"] = result.ID
	eventInfo["dc_hostname"] = dcHostname
	eventInfo["timestamp"] = result.Timestamp
	eventInfo["unique_id"] = result.UniqueId
	eventInfo["unique_key"] = strings.Join(rule.UniqueFields, ",")

	for field, val := range result.Fields {
		k := fmt.Sprintf("field_%s", field)
		eventInfo[k] = val
	}

	cacheId := fmt.Sprintf("%s_%s", common.AlertActivityCachePrefix, mId)
	err := e.redisCli.HMSet(ctx, cacheId, eventInfo).Err()
	if err != nil {
		logger.Errorf("hmset event_info(mid:%s) err:%v", mId, err)
		return "", err
	}
	// 所有的activity最长保存6h（意味着flow的关联能力是6h内的数据）
	if err := e.redisCli.Expire(ctx, cacheId, common.MaxFlowWinSize*time.Second).Err(); err != nil {
		logger.Errorf("set event_info expire err:%v", err)
		return "", err
	}

	return cacheId, nil
}

// syncFlowEngine flow引擎执行逻辑
// zset+activity_cache 资源预估:
// 假设单条 zset+activity_cache 约为10KB，则5GB redis cache并满足6h存储的情况下，最多24条activity日志/秒（是指sigma匹配到之后的日志）。
func (e *EngineWorker) syncFlowEngine(ctx context.Context, eId, mId, dcHostname string, result sigma.Result, rule *sigma.Rule) error {
	v, err := e.redisCli.HGet(ctx, common.FlowRuleMapKey, rule.ID).Result()
	if err != nil {
		if err == redis.Nil {
			logger.Debugf("get empty flows by sid(%s)", rule.ID)
			return nil
		}
		return err
	}

	for _, flowId := range strings.Split(v, ",") {
		// set rule info into cache
		cacheId, err := e.cacheActivityMeta(ctx, eId, mId, dcHostname, result, rule)
		if err != nil {
			logger.Warnf("cache event(mId:%s, sid:%s) err:%v, will ignore!", mId, result.ID, err)
			continue
		}

		// set zset
		zsetKey := fmt.Sprintf("%s:%s_%s", common.FlowInstancePrefixKey, flowId, result.UniqueId)
		err = e.redisCli.ZAdd(ctx, zsetKey, redis.Z{Score: float64(result.Timestamp), Member: cacheId}).Err()
		if err != nil {
			logger.Warnf("set zset err:%v", err)
			continue
		}
		if err := e.redisCli.Expire(ctx, zsetKey, common.MaxFlowWinSize*time.Second).Err(); err != nil {
			logger.Warnf("set zset expire err:%v", err)
			continue
		}
	}

	return nil
}

// cacheInternalActivity 将内置规则产生的fields等数据cache到redis指定的缓存中，以便其他查询使用
func (e *EngineWorker) cacheInternalActivity(ctx context.Context, result sigma.Result, rule *sigma.Rule) {
	var err error
	// 内置的rdx_key定义如下:
	// rule_cache:aduser_info # ada:engine:rule_cache:aduser_info  4624用户登录成功的日志, 关联:UserName,UserSid,AddressIP,Timestamp
	//
	//
	switch rule.RdxKey {
	case "rule_cache:aduser_info":
		var domain string
		eventInfo := make(map[string]interface{})
		eventInfo["timestamp"] = result.Timestamp
		for field, val := range result.Fields {
			switch field {
			case "Hostname":
				eventInfo["dc_hostname"] = val
			case "TargetUserName":
				eventInfo["name"] = val
			case "TargetUserSid":
				eventInfo["sid"] = val
			case "IpAddress":
				eventInfo["ip"] = val
			case "TargetDomainName":
				domain = val
			}
		}
		cacheId := fmt.Sprintf("ada:engine:%s:%s", strings.ToLower(domain), rule.RdxKey)
		err = e.redisCli.HMSet(ctx, cacheId, eventInfo).Err()
	case "rule_cache:adgroup_info":
		//
	default:
		logger.Warnf("invalid rdx_key:%s in rule:%s, will ignore!", rule.RdxKey, rule.Title)
	}

	if err != nil {
		logger.Errorf("hmset internal_cache(%s) err:%v", rule.RdxKey, err)
	}
}
