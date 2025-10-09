package core

import (
	"ada/engine/common"
	"ada/engine/config"
	"ada/engine/flow"
	"ada/engine/sigma"
	"ada/infra/base"
	"ada/infra/license"
	"ada/infra/mongo"
	"context"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

const activityIndexMapping = `{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": {
    "properties": {
      "@timestamp": {
        "type": "date"
      }
    }
  }
}`

type EngineWorker struct {
	ctx        context.Context
	redisCli   *redis.Client
	mongoCli   mongo.DBAdaptor
	esCli      *elasticsearch.Client
	ruleset    map[string]*sigma.Ruleset
	Flowset    *flow.Ruleset // TODO: 单元测试需要，后期改为flowset
	cancel     context.CancelFunc
	workerStop bool
	mu         sync.RWMutex // 读写锁，用于保护pending
	pending    bool         // 如果license校验不过，该值为true(engine处于不处理数据状态)
}

func New(env *config.Env) (*EngineWorker, error) {
	ctx, cancel := context.WithCancel(context.Background())

	ruleset := make(map[string]*sigma.Ruleset)

	flowRulePath := filepath.Join(common.RuleDir, common.RuleFlow)
	winLogRulePath := filepath.Join(common.RuleDir, common.RuleWinLog)
	pktLogRulePath := filepath.Join(common.RuleDir, common.RulePktLog)

	// init sigma flow ruleset（必须在sigma rule初始化执行）
	flowset, err := flow.NewRuleset(env.RedisCli, env.MongoCli, flowRulePath)
	if err != nil {
		logger.Errorf("init flow ruleset err %v", err)
		cancel()
		return nil, err
	}

	logger.Infof("loaded flow ruleset form %s", flowRulePath)

	// 遍历flowset中的所有flow Fields，按sigma_id进行map, {"sigma_id": ["field1", "field2", ...]}
	var sigmaExtFields = make(map[string][]string)
	for _, f := range flowset.FlowRules {
		for sid, fields := range f.ExtFields {
			// fields 更新
			if v, ok := sigmaExtFields[sid]; ok {
				sigmaExtFields[sid] = append(v, fields...) // sigmaRuleFields[sid]中可能存在重复field，但不影响(margeFields会去重)
				sigmaExtFields[sid] = base.RemoveDuplicate(sigmaExtFields[sid])
			} else {
				sigmaExtFields[sid] = base.RemoveDuplicate(fields)
			}
		}
	}

	// init sigma ruleset
	winLogRule, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{winLogRulePath},
		NoCollapseWS:    false,
		FailOnRuleParse: false,
		FailOnYamlParse: false,
		ExtractFields:   sigmaExtFields,
	}, nil)
	if err != nil {
		logger.Errorf("init sigma ruleset err %v", err)
		cancel()
		return nil, err
	}
	ruleset[common.RuleWinLog] = winLogRule

	logger.Infof("loaded winlog ruleset, totoal:%d, failed:%d, unsupported:%d", winLogRule.Total, winLogRule.Failed, winLogRule.Unsupported)

	pktLogRule, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{pktLogRulePath},
		NoCollapseWS:    false,
		FailOnRuleParse: false,
		FailOnYamlParse: false,
		ExtractFields:   sigmaExtFields,
	}, nil)
	if err != nil {
		logger.Errorf("init sigma ruleset err %v", err)
		cancel()
		return nil, err
	}
	ruleset[common.RulePktLog] = pktLogRule

	logger.Infof("loaded pktlog ruleset, totoal:%d, failed:%d, unsupported:%d", pktLogRule.Total, pktLogRule.Failed, pktLogRule.Unsupported)

	// check if all the flow rule's `SigmaID` in sigma ruleset.
	for sid, _ := range sigmaExtFields {
		if winLogRule.GetRule(sid) == nil && pktLogRule.GetRule(sid) == nil {
			logger.Warnf("flow related sigma_id(%s) not found in sigma ruleset", sid)
		}
	}

	return &EngineWorker{ctx: ctx, redisCli: env.RedisCli, mongoCli: env.MongoCli, esCli: env.ESCli, ruleset: ruleset, Flowset: flowset, cancel: cancel}, nil
}

func (e *EngineWorker) Setup() error {
	// 将flow相关sigma规则的map映射更新到cache中
	if err := e.Flowset.LoadRuleCache(); err != nil {
		return err
	}

	// 将flow相关联的:所有sigma规则的fields 和 flow match_by中的extFields 去重合并，然后cache redis中（api GetThreatWhitelistFields需要）
	var flowAllFields = make(map[string][]string) // flow_id -> (all sigma_id) fields
	for _, f := range e.Flowset.FlowRules {
		var fields []string
		for sid, item := range f.ExtFields { // 这里的Fields
			fields = append(fields, item...)

			for _, sigmaRules := range e.ruleset {
				if v, ok := sigmaRules.FieldsMap[sid]; ok {
					fields = append(fields, v...)
					break
				}
			}
		}

		if v, ok := flowAllFields[f.ID]; ok {
			flowAllFields[f.ID] = append(v, fields...)
			flowAllFields[f.ID] = base.RemoveDuplicate(flowAllFields[f.ID])
		} else {
			flowAllFields[f.ID] = base.RemoveDuplicate(fields)
		}
	}

	// delete all the old flow fields cache
	ctx := context.Background()
	err := e.redisCli.Del(ctx, common.FlowFieldMapKey).Err()
	if err != nil {
		logger.Errorf("delete old flow fields cache err:%v", err)
		return err
	}

	// add all flow related sigma fields to cache
	// type: hash field: flow_id value: fields(split by ",")
	fieldMap := make(map[string]string)
	for flowId, fields := range flowAllFields {
		fieldMap[flowId] = strings.Join(fields, ",")
	}
	err = e.redisCli.HMSet(ctx, common.FlowFieldMapKey, fieldMap).Err()
	if err != nil {
		logger.Errorf("setup flow fields cache err:%v", err)
		return err
	}

	if e.esCli == nil {
		logger.Infof("ES disabled, skip create index")
		return nil
	}

	// check if the index(ada-activity(common.AlertActivityIndexKey)) is created. if not, create first.
	req := esapi.IndicesExistsRequest{Index: []string{common.AlertActivityIndexKey}}
	r, err := req.Do(context.Background(), e.esCli)
	if err != nil {
		logger.Errorf("request es err:%v", err)
		return err
	}
	defer r.Body.Close()

	// is index doesn't exist, the status_code is 404
	if r.StatusCode == 404 {
		// create index
		req := esapi.IndicesCreateRequest{
			Index: common.AlertActivityIndexKey,
			Body:  strings.NewReader(activityIndexMapping),
		}
		res, err := req.Do(context.Background(), e.esCli)
		if err != nil {
			logger.Errorf("Error getting response: %s", err)
			return err
		}
		defer res.Body.Close()
	}

	return nil
}

func (e *EngineWorker) Stop() {
	e.cancel()
	e.workerStop = true
}

func (e *EngineWorker) FlowMatcher() {
	// run as goroutine to match flow event
	for {
		time.Sleep(1 * time.Second)

		if e.pending {
			continue
		}

		if e.workerStop {
			return
		}

		start := time.Now().Unix()
		e.Flowset.FlowMatcher() // TODO: 串行执行（不要并发），如何防止卡住？？

		// 计算执行一次FlowMatcher()所使用时间，如果超出默认最大值(240s)
		if time.Now().Unix()-start > 240 {
			logger.Warn("[warnning] FlowMatcher took much time(more than 240s)!!")
		}
	}
}

func (e *EngineWorker) FlowCleaner() {
	// run as goroutine to clean expire flow event data in redis
	ticker := time.NewTicker(120 * time.Second) // 2min 进行一次清理
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			e.Stop()
			return
		case <-ticker.C:
			{
				e.Flowset.FlowCleaner() // 串行执行（无需并发）
			}
		}
	}
}

func (e *EngineWorker) SigmaMatcher() {
	// run as serve to match eventlog and packetlog by sigma rule
	ctx := context.Background()

	for {
		if e.workerStop {
			ctx.Done()
			return
		}
		msg, err := e.redisCli.BRPop(ctx, 3*time.Second, common.EveLogQueueKey, common.PktLogQueueKey).Result()
		if err != nil {
			if er := e.redisCli.Ping(ctx).Err(); er != nil {
				logger.Errorf("redis ping failure:%v", er)
				e.workerStop = true // 通知其他goroutine也退出
				return
			}
			continue
		}
		// msg format: []string{"ada:evelog_queue", "json_message"}
		if len(msg) != 2 {
			logger.Warnf("ignore invalid length msg:%v", msg)
			continue
		}

		//logger.Debugf("channel: %s received:%s", msg[0], msg[1])

		go e.sigmaRuleMatcher(ctx, msg[0], msg[1])
	}
}

func (e *EngineWorker) RuntimeCheck() {
	checkTicker := time.NewTicker(30 * time.Second)
	defer checkTicker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			e.Stop()
			return
		case <-checkTicker.C:
			{
				if e.expired() {
					e.Stop()
					return
				}
			}
		}
	}
}

func (e *EngineWorker) expired() bool {
	defer e.mu.Unlock()
	lic, err := license.NewAdaLicense(e.redisCli)
	if err != nil {
		//logger.Errorf("init license err:%v", err) // TODO: 在release版本开启
		e.mu.Lock()
		e.pending = true
		return false
	}

	if lic.Expired() == false {
		e.mu.Lock()
		e.pending = false
	} else {
		e.mu.Lock()
		e.pending = true
	}

	if lic.DelayExpired() {
		return true
	}

	return false
}
