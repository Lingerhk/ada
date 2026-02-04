package flow

import (
	"ada/engine/common"
	"ada/infra/mongo"
	utime "ada/infra/time"
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

type flowActivity struct {
	timestamp     int64             // score: timestamp
	activityId    string            // member: AlertActivityCachePrefix_mid
	activityCache map[string]string // engine/core/match.go:cacheEvent()
}

type Ruleset struct {
	redisCli      *redis.Client
	mongoCli      mongo.DBAdaptor
	FlowRules     []FlowRule
	sigmaRuleTTLs map[string]int64 // sigma_id -> (max)ttl, 在FlowCleaner中按max ttl进行activity清理
}

func NewRuleset(redisCli *redis.Client, mongoCli mongo.DBAdaptor, flowRuleDir string) (*Ruleset, error) {
	// read flow rule from dir
	files, err := NewRuleFileList([]string{flowRuleDir})
	if err != nil {
		return nil, err
	}

	// load flow rules
	flowRules, err := NewRuleList(files)
	if err != nil {
		return nil, err
	}

	var sigmaRuleTTLs = make(map[string]int64) // sigma_id -> (max)ttl 在FlowCleaner中按max ttl进行activity清理
	for _, f := range flowRules {
		for sid, _ := range f.ExtFields {
			winSize, _ := utime.ConvertStrTime(f.Detection.WinSize)
			if ttl, ok := sigmaRuleTTLs[sid]; ok && ttl < winSize {
				sigmaRuleTTLs[sid] = winSize
			} else {
				sigmaRuleTTLs[sid] = winSize
			}
		}
	}

	return &Ruleset{redisCli: redisCli, mongoCli: mongoCli, FlowRules: flowRules, sigmaRuleTTLs: sigmaRuleTTLs}, nil
}

// FlowCleaner 执行flow event, 产生多事件关联告警
func (r *Ruleset) FlowCleaner(ctx context.Context) {
	// 遍历每个flow_rule, 按win_size最大值 进行清理
	// 遍历所有flow event(zset)暂存数据, 如果有过期的,执行清理
	// 1.zset 数据较多并且 last(300 member) timestamp超过12h未更新的, 删除超过18h的数据
	// 2.zset max(timestamp) member超过12h未更新, 整个zset删除
	// 3.涉及到的其他（如raw log）删除

	for _, fr := range r.FlowRules {
		flowInstances := r.getFlowInstances(ctx, fr.ID)
		if len(flowInstances) == 0 {
			continue
		}

		currTs := time.Now().UnixNano() / 1e6
		for _, instancesId := range flowInstances {
			// get scores as timestamp, check it with the win_size for each activity
			zs, err := r.redisCli.ZRangeWithScores(ctx, instancesId, 0, -1).Result()
			if err != nil {
				logger.Warnf("range_with_scores zset err:%v", err)
				continue
			}

			for _, z := range zs {
				val, err := r.getActivityCache(ctx, z.Member.(string))
				if err != nil {
					logger.Warnf("get instance_cache err:%v, will ignore!", err)
					continue
				}
				sid, ok := val["sid"]
				if !ok {
					continue
				}
				ttl, ok := r.sigmaRuleTTLs[sid]
				if !ok {
					continue
				}
				if currTs-int64(z.Score) > (ttl+10)*1000 {
					logger.Debugf("clean flow instance(%s) by ttl(%d)", z.Member.(string), ttl)

					// delete zset member first
					if err := r.redisCli.ZRem(ctx, instancesId, z.Member).Err(); err != nil {
						logger.Warnf("delete flow instance's member(%s) err:%v", z.Member.(string), err)
						continue
					}

					if err := r.redisCli.Del(ctx, z.Member.(string)).Err(); err != nil {
						logger.Warnf("delete flow instance's activity by member(%s) err:%v", z.Member.(string), err)
						continue
					}
				}
			}
		}
	}
}

// FlowMatcher 执行flow event匹配, 产生多事件关联告警
func (r *Ruleset) FlowMatcher(ctx context.Context) {
	// 遍历所有flow event(zset), 如果有满足多事件条件的，产生关联告警
	for _, fr := range r.FlowRules {
		flowInstances := r.getFlowInstances(ctx, fr.ID)
		if len(flowInstances) == 0 {
			//logger.Debugf("ignore empty instance for flow:%s", fr.ID)
			continue
		}

		switch fr.Detection.EventType {
		case common.EventTypeCount:
			logger.Debugf("handle EventTypeCount instances %v", flowInstances)
			r.matchEventCount(ctx, fr, flowInstances)
		case common.EventTypeMultiEve:
			logger.Debugf("handle EventTypeMultiEve instances %v", flowInstances)
			r.matchEventMultiEve(ctx, fr, flowInstances)
		case common.EventTypeMultiPkt:
			r.matchEventMultiPkt(ctx, fr, flowInstances)
		case common.EventTypeMultiEvePkt:
			r.matchEventMultiEvePkt(ctx, fr, flowInstances)
		}
	}
}

func (r *Ruleset) getFlowInstances(ctx context.Context, flowId string) []string {
	activeKey := fmt.Sprintf("%s:%s", common.FlowActiveSetPrefixKey, flowId)
	instances, err := r.redisCli.SMembers(ctx, activeKey).Result()
	if err == nil && len(instances) > 0 {
		// prune dead instance keys (best-effort)
		for _, k := range instances {
			if r.redisCli.Exists(ctx, k).Val() == 0 {
				_ = r.redisCli.SRem(ctx, activeKey, k).Err()
			}
		}
		return instances
	}

	// fallback (compat): old deployments might not have active set yet
	return r.redisCli.Keys(ctx, fmt.Sprintf("%s:%s_*", common.FlowInstancePrefixKey, flowId)).Val()
}

func (r *Ruleset) getActivityCache(ctx context.Context, instancesId string) (map[string]string, error) {
	val, err := r.redisCli.HGetAll(ctx, instancesId).Result()
	if err != nil {
		if err == redis.Nil {
			return nil, nil
		}
		return nil, err
	}

	return val, nil
}

func (r *Ruleset) getFlowActivitiesByWinSize(ctx context.Context, instancesId string, winSize, stop int64) ([]flowActivity, error) {
	// 从zset中按Timestamp，取出指定的Member list.
	start := stop - winSize*1000

	// 默认按照分数从小到大排列
	logger.Debugf("getFlowActivitiesByWinSize(ins_id:%s): win_size:%d start: %d stop: %d", instancesId, winSize, start, stop)

	opt := redis.ZRangeBy{Min: strconv.FormatInt(start, 10), Max: strconv.FormatInt(stop, 10)}
	zs, err := r.redisCli.ZRangeByScoreWithScores(ctx, instancesId, &opt).Result()
	if err != nil {
		logger.Warnf("range_with_scores zset err:%v", err)
		return nil, err
	}

	var activities []flowActivity
	for _, z := range zs {
		val, err := r.getActivityCache(ctx, z.Member.(string))
		if err != nil {
			logger.Warnf("get instance_cache err:%v, will ignore!", err)
			continue
		}

		activities = append(activities, flowActivity{
			timestamp:     int64(z.Score),
			activityId:    z.Member.(string),
			activityCache: val,
		})
	}

	return activities, nil
}

func (r *Ruleset) checkUniqueFilter(ctx context.Context, flowId string, uniqueFilter []string, acts []flowActivity) bool {
	if len(uniqueFilter) == 0 {
		return false
	}

	filerKey := fmt.Sprintf("ada:engine:flow_filter:%s", flowId)

	for _, field := range uniqueFilter {
		if strings.HasPrefix(field, "ttl_") {
			continue
		}

		idx, val := parseConditionKV(field)
		if idx == -1 || val == "" {
			continue
		}

		if len(acts)-1 < int(idx) {
			logger.Warnf("ignore unique filter item by index(%d), unique_item:%s)", idx, field)
			continue
		}

		fieldVal := getFieldVal(val, acts[idx])
		filerKey += fmt.Sprintf(":%s", strings.ToLower(fieldVal))
	}

	if r.redisCli.Exists(ctx, filerKey).Val() == 1 {
		return true
	}
	return false
}

func (r *Ruleset) addUniqueFilter(ctx context.Context, flowId string, uniqueFilter []string, acts []flowActivity) error {
	if len(uniqueFilter) == 0 {
		return nil
	}

	filerKey := fmt.Sprintf("ada:engine:flow_filter:%s", flowId)

	var uniqueFilterTtl int
	for _, field := range uniqueFilter {
		if strings.HasPrefix(field, "ttl_") {
			ttl, err := strconv.Atoi(strings.TrimPrefix(field, "ttl_"))
			if err != nil {
				logger.Warnf("ignore unique filter ttl by extract ttl(%s) from unique_item:%s) failed", field, uniqueFilter)
				continue
			}
			uniqueFilterTtl = ttl
			continue
		}

		idx, val := parseConditionKV(field)
		if idx == -1 || val == "" {
			continue
		}

		if len(acts)-1 < int(idx) {
			logger.Warnf("ignore unique filter item by index(%d), unique_item:%s)", idx, field)
			continue
		}

		fieldVal := getFieldVal(val, acts[idx])
		filerKey += fmt.Sprintf(":%s", strings.ToLower(fieldVal))
	}

	err := r.redisCli.Set(ctx, filerKey, "1", time.Duration(uniqueFilterTtl)*time.Second).Err()
	if err != nil {
		logger.Warnf("set unique filter(%s) err:%v", filerKey, err)
		return err
	}

	return nil
}
