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
	"runtime"
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
	ctx      context.Context
	redisCli *redis.Client
	mongoCli mongo.DBAdaptor
	esCli    *elasticsearch.Client

	esIndexer *ESIndexer

	ruleset map[string]*sigma.Ruleset
	Flowset *flow.Ruleset
	cancel  context.CancelFunc

	mu      sync.RWMutex // protects ruleset/Flowset and state
	pending bool         // 如果license校验不过，该值为true(engine处于不处理数据状态)
	stopped bool

	sigmaWorkers int
	sigmaTimeout time.Duration
}

func New(env *config.Env) (*EngineWorker, error) {
	ctx, cancel := context.WithCancel(context.Background())

	ruleset := make(map[string]*sigma.Ruleset)

	flowRulePath := filepath.Join(common.RuleDir, common.RuleFlow)
	winLogRulePath := filepath.Join(common.RuleDir, common.RuleWinLog)
	pktLogRulePath := filepath.Join(common.RuleDir, common.RulePktLog)

	// init sigma flow ruleset（必须在sigma rule初始化执行）
	var err error
	var flowset *flow.Ruleset
	for {
		time.Sleep(3 * time.Second)
		flowset, err = flow.NewRuleset(env.RedisCli, env.MongoCli, flowRulePath)
		if err == flow.ErrMissingRuleList {
			logger.Warnf("empty rules %v, wait 20s...", err)
			time.Sleep(20 * time.Second)
			continue
		}

		if err != nil {
			logger.Errorf("init flow ruleset err %v", err)
			cancel()
			return nil, err
		}
		break
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
		logger.Errorf("init winlog ruleset err %v", err)
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
		logger.Errorf("init pktlog ruleset err %v", err)
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

	w := &EngineWorker{
		ctx:          ctx,
		redisCli:     env.RedisCli,
		mongoCli:     env.MongoCli,
		esCli:        env.ESCli,
		ruleset:      ruleset,
		Flowset:      flowset,
		cancel:       cancel,
		sigmaWorkers: 8 * runtime.NumCPU(),
		sigmaTimeout: 8 * time.Second,
	}
	if w.esCli != nil {
		w.esIndexer = NewESIndexer(w.ctx, w.esCli, common.AlertActivityIndexKey, 200, 3*time.Second)
	}
	return w, nil
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
	e.mu.Lock()
	e.stopped = true
	e.mu.Unlock()
}

// Reload reloads all rule files from disk without stopping the engine
func (e *EngineWorker) Reload() error {
	logger.Infof("Reloading rules from %s...", common.RuleDir)

	flowRulePath := filepath.Join(common.RuleDir, common.RuleFlow)
	winLogRulePath := filepath.Join(common.RuleDir, common.RuleWinLog)
	pktLogRulePath := filepath.Join(common.RuleDir, common.RulePktLog)

	// Reload flow ruleset
	newFlowset, err := flow.NewRuleset(e.redisCli, e.mongoCli, flowRulePath)
	if err != nil {
		logger.Errorf("Failed to reload flow ruleset: %v", err)
		return err
	}
	logger.Infof("Reloaded flow ruleset from %s", flowRulePath)

	// Rebuild sigma extended fields map from new flowset
	var sigmaExtFields = make(map[string][]string)
	for _, f := range newFlowset.FlowRules {
		for sid, fields := range f.ExtFields {
			if v, ok := sigmaExtFields[sid]; ok {
				sigmaExtFields[sid] = append(v, fields...)
				sigmaExtFields[sid] = base.RemoveDuplicate(sigmaExtFields[sid])
			} else {
				sigmaExtFields[sid] = base.RemoveDuplicate(fields)
			}
		}
	}

	// Reload sigma rulesets
	newWinLogRule, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{winLogRulePath},
		NoCollapseWS:    false,
		FailOnRuleParse: false,
		FailOnYamlParse: false,
		ExtractFields:   sigmaExtFields,
	}, nil)
	if err != nil {
		logger.Errorf("Failed to reload winlog ruleset: %v", err)
		return err
	}
	logger.Infof("Reloaded winlog ruleset, total:%d, failed:%d, unsupported:%d", newWinLogRule.Total, newWinLogRule.Failed, newWinLogRule.Unsupported)

	newPktLogRule, err := sigma.NewRuleset(sigma.Config{
		Directory:       []string{pktLogRulePath},
		NoCollapseWS:    false,
		FailOnRuleParse: false,
		FailOnYamlParse: false,
		ExtractFields:   sigmaExtFields,
	}, nil)
	if err != nil {
		logger.Errorf("Failed to reload pktlog ruleset: %v", err)
		return err
	}
	logger.Infof("Reloaded pktlog ruleset, total:%d, failed:%d, unsupported:%d", newPktLogRule.Total, newPktLogRule.Failed, newPktLogRule.Unsupported)

	// Check flow-sigma rule consistency
	for sid := range sigmaExtFields {
		if newWinLogRule.GetRule(sid) == nil && newPktLogRule.GetRule(sid) == nil {
			logger.Warnf("Flow related sigma_id(%s) not found in sigma ruleset", sid)
		}
	}

	// Atomically replace old rulesets with new ones (thread-safe)
	e.mu.Lock()
	e.Flowset = newFlowset
	e.ruleset[common.RuleWinLog] = newWinLogRule
	e.ruleset[common.RulePktLog] = newPktLogRule
	e.mu.Unlock()

	// Reload rule cache
	if err := e.Flowset.LoadRuleCache(); err != nil {
		logger.Errorf("Failed to reload rule cache: %v", err)
		return err
	}

	// Update flow fields cache
	var flowAllFields = make(map[string][]string)
	for _, f := range e.Flowset.FlowRules {
		var fields []string
		for sid, item := range f.ExtFields {
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

	// Update Redis cache
	ctx := context.Background()
	err = e.redisCli.Del(ctx, common.FlowFieldMapKey).Err()
	if err != nil {
		logger.Errorf("Failed to delete old flow fields cache: %v", err)
		return err
	}

	fieldMap := make(map[string]string)
	for flowId, fields := range flowAllFields {
		fieldMap[flowId] = strings.Join(fields, ",")
	}
	err = e.redisCli.HMSet(ctx, common.FlowFieldMapKey, fieldMap).Err()
	if err != nil {
		logger.Errorf("Failed to update flow fields cache: %v", err)
		return err
	}

	logger.Info("Rules reloaded successfully")
	return nil
}

func (e *EngineWorker) FlowMatcher() {
	// run as goroutine to match flow event
	for {
		time.Sleep(1 * time.Second)

		e.mu.RLock()
		pending := e.pending
		stopped := e.stopped
		flowset := e.Flowset
		e.mu.RUnlock()

		if pending {
			continue
		}
		if stopped {
			return
		}

		start := time.Now().Unix()

		// 每轮兜底超时: 5min；避免FlowMatcher永久卡死
		ctx, cancel := context.WithTimeout(e.ctx, 5*time.Minute)
		flowset.FlowMatcher(ctx)
		cancel()

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
				e.mu.RLock()
				flowset := e.Flowset
				e.mu.RUnlock()
				ctx, cancel := context.WithTimeout(e.ctx, 2*time.Minute)
				flowset.FlowCleaner(ctx) // 串行执行（无需并发）
				cancel()
			}
		}
	}
}

func (e *EngineWorker) SigmaMatcher() {
	// run as serve to match eventlog and packetlog by sigma rule
	ctx := e.ctx

	type job struct {
		channel string
		payload string
	}

	jobs := make(chan job, 4096)

	// fixed worker pool (avoid unbounded goroutines)
	for i := 0; i < e.sigmaWorkers; i++ {
		go func() {
			for j := range jobs {
				jctx, cancel := context.WithTimeout(ctx, e.sigmaTimeout)
				e.sigmaRuleMatcher(jctx, j.channel, j.payload)
				cancel()
			}
		}()
	}

	for {
		e.mu.RLock()
		stopped := e.stopped
		e.mu.RUnlock()
		if stopped {
			close(jobs)
			return
		}

		msg, err := e.redisCli.BRPop(ctx, 3*time.Second, common.EveLogQueueKey, common.PktLogQueueKey).Result()
		if err != nil {
			if er := e.redisCli.Ping(ctx).Err(); er != nil {
				logger.Errorf("redis ping failure:%v", er)
				e.Stop()
				close(jobs)
				return
			}
			continue
		}

		// msg format: []string{"ada:evelog_queue", "json_message"}
		if len(msg) != 2 {
			logger.Warnf("ignore invalid length msg:%v", msg)
			continue
		}

		select {
		case jobs <- job{channel: msg[0], payload: msg[1]}:
		case <-ctx.Done():
			close(jobs)
			return
		}
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

// RuleReloader listens for reload signals from Redis pub/sub
func (e *EngineWorker) RuleReloader() {
	ctx := context.Background()
	pubsub := e.redisCli.Subscribe(ctx, common.EngineReloadChannel)
	defer pubsub.Close()

	logger.Infof("Listening for reload signals on Redis channel '%s'", common.EngineReloadChannel)

	// Wait for confirmation that subscription is created
	_, err := pubsub.Receive(ctx)
	if err != nil {
		logger.Errorf("Failed to subscribe to reload channel: %v", err)
		return
	}

	// Create channel for receiving messages
	ch := pubsub.Channel()

	for {
		select {
		case <-e.ctx.Done():
			return
		case msg := <-ch:
			logger.Infof("Received reload signal: %s", msg.Payload)
			if err := e.Reload(); err != nil {
				logger.Errorf("Failed to reload rules: %v", err)
			} else {
				logger.Info("Rules reloaded successfully via Redis signal")
			}
		}
	}
}

func (e *EngineWorker) expired() bool {
	e.mu.Lock()
	defer e.mu.Unlock()

	lic, err := license.NewAdaLicense(e.redisCli)
	if err != nil {
		//logger.Errorf("init license err:%v", err) // TODO: 在release版本开启
		e.pending = true
		return false
	}

	if !lic.Expired() {
		e.pending = false
	} else {
		e.pending = true
	}

	if lic.DelayExpired() {
		return true
	}

	return false
}
