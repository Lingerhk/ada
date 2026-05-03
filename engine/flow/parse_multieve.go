package flow

import (
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"strings"
	"time"
)

// 匹配器: 多条winlog类型
func (r *Ruleset) matchEventMultiEve(ctx context.Context, fr FlowRule, flowInstances []string) {
	r.matchEventSequence(ctx, fr, flowInstances, "multi-eve")
}

func (r *Ruleset) matchEventSequence(ctx context.Context, fr FlowRule, flowInstances []string, eventName string) {
	for _, insId := range flowInstances {
		func() {
			insCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()

			stop := time.Now().UnixNano() / 1e6

			logger.Debugf("handle %s instance_id %s", eventName, insId)

			// 取最新winSize内的所有事件
			activities, err := r.getFlowActivitiesByWinSize(insCtx, insId, fr.Detection.WinSizeTs, stop)
			if err != nil {
				logger.Warnf("get flow events by win_size err:%v, will ignore this event!", err)
				return
			}
			if len(activities) == 0 {
				return
			}

			validSets := r.extractActivities(activities, fr.Detection.SigmaRules, fr.Detection.WinSizeTs, fr.Detection.Sorted)
			if len(validSets) == 0 {
				return
			}

			matchedActivities, matched := r.matchByActivities(insCtx, activities, validSets, fr.Detection.MatchBy)
			if !matched {
				return
			}

			// 对flow事件进行unique_filter过滤
			if r.checkUniqueFilter(insCtx, fr.ID, fr.UniqueFilter, matchedActivities) {
				logger.Debugf("ignore flow instance(%s) by matched unique_filter:%s", insId, fr.UniqueFilter)
				return
			}

			// 匹配到flow告警
			logger.Debugf("matched flow from activities: %v", matchedActivities)

			if err := r.storeEvent(insCtx, insId, fr, matchedActivities); err != nil {
				logger.Warnf("store event(%s) err:%v, will ignore this flow instance!", eventName, err)
			}

			// 如果存在unique_filter，则添加到redis cache中
			if err := r.addUniqueFilter(insCtx, fr.ID, fr.UniqueFilter, matchedActivities); err != nil {
				logger.Warnf("add unique_filter(flow_insId:%s,filter: %s) err:%v", insId, fr.UniqueFilter, err)
			}

			if err := r.redisCli.Del(insCtx, insId).Err(); err != nil {
				logger.Warnf("delete flow instance(%s) err:%v", eventName, err)
			}
		}()
	}
}

func (r *Ruleset) extractActivities(activities []flowActivity, sigmaIds []string, winSize int64, sorted bool) [][]int64 {
	sigIdTypes := make(map[int][]int64)

	for sIdx, _ := range sigmaIds {
		sigIdTypes[sIdx] = []int64{}
	}

	// 分组
	/**************************************************/
	// 最终获取到N组(SigmaRules list)已经分组后的结果(下标), S代表 sigma_id
	// S1: [1,3,6]
	// S2: [2,5,9]
	// S3: [4,7]

	for aIdx, act := range activities {
		if len(act.activityCache) == 0 {
			continue
		}

		if val, ok := act.activityCache["sid"]; ok {
			for sIdx, sigmaId := range sigmaIds {
				if val == sigmaId {
					sigIdTypes[sIdx] = append(sigIdTypes[sIdx], int64(aIdx))
					continue
				}
			}
		}
	}

	// 排列组合
	/**************************************************/
	// 对S1/S2/S3进行排列组合：S1: [1,3,6]; S2: [2,5,9]; S3: [4,7]
	// 然后安装winSize 获取不符合要求的组合

	var fullSet [][]int64 // 定义所有排列组合的结果

	// 递归函数
	var dfs func(idx int, cur []int64)
	dfs = func(idx int, cur []int64) {
		// 递归终止条件
		if idx == len(sigIdTypes) {
			fullSet = append(fullSet, cur)
			return
		}

		// 遍历当前层的所有元素
		for _, v := range sigIdTypes[idx] {
			// 如果sorted为true，则判断当前元素是否大于前一个元素，如果不是则过滤掉该组合
			if sorted && (len(cur) > 0 && v <= cur[len(cur)-1]) {
				continue
			}

			// 将元素添加到当前组合中
			newCur := make([]int64, len(cur))
			copy(newCur, cur)
			newCur = append(newCur, v)
			// 递归下一层
			dfs(idx+1, newCur)
		}
	}

	// 开始递归
	dfs(0, []int64{})

	var validSet [][]int64 // 定义最终按winSize过滤后的所有排列组合的结果

	for _, v := range fullSet {
		// 按照winSize过滤
		max := v[0]
		min := v[0]
		for _, n := range v {
			if n > max {
				max = n
			}
			if n < min {
				min = n
			}
		}

		// timestamp的单位是毫秒
		if activities[max].timestamp-activities[min].timestamp <= winSize*1000 {
			validSet = append(validSet, v)
		}
	}

	return validSet
}

func (r *Ruleset) matchByActivities(ctx context.Context, activities []flowActivity, validSets [][]int64, matchBy string) ([]flowActivity, bool) {
	matchExpr, _, err := parseMatchExpression(matchBy)
	if err != nil {
		logger.Warnf("parse match_by(%s) err:%v, will ignore this flow", matchBy, err)
		return nil, false
	}
	activityCount := int64(len(activities))

	for _, validSet := range validSets {
		var actList []flowActivity
		for _, actIdx := range validSet {
			if actIdx > activityCount-1 {
				continue
			}

			actList = append(actList, activities[actIdx])
		}

		matched := r.matchExpr(ctx, matchExpr, actList...)
		if matched {
			// TODO：如果match多条，这里就只取第一条了。。。
			return actList, true
		}
	}

	return nil, false
}

func (r *Ruleset) matchExpr(ctx context.Context, expr *matchExprNode, activity ...flowActivity) bool {
	if expr == nil {
		return false
	}

	switch expr.kind {
	case matchExprCondition:
		return r.matchCondition(ctx, expr.condition, activity...)
	case matchExprAnd:
		return r.matchExpr(ctx, expr.left, activity...) && r.matchExpr(ctx, expr.right, activity...)
	case matchExprOr:
		return r.matchExpr(ctx, expr.left, activity...) || r.matchExpr(ctx, expr.right, activity...)
	case matchExprNot:
		return !r.matchExpr(ctx, expr.left, activity...)
	default:
		return false
	}
}

func (r *Ruleset) match(ctx context.Context, conditions []Condition, activity ...flowActivity) bool {
	// 遍历表达式中的每个子句
	for _, c := range conditions {
		if !r.matchCondition(ctx, c, activity...) {
			return false
		}
	}

	return true
}

func (r *Ruleset) matchCondition(ctx context.Context, c Condition, activity ...flowActivity) bool {
	if !c.valid || c.fieldOneIdx < 0 || int(c.fieldOneIdx) >= len(activity) {
		return false
	}
	v1 := getFieldVal(c.fieldOneVal, activity[c.fieldOneIdx])

	if c.operation == "in" {
		switch c.fieldTwoTyp {
		case "slice":
			inSlice := false
			for _, v := range strings.Split(c.fieldTwoVal, ",") {
				if v1 == v {
					inSlice = true
					break
				}
			}
			if !inSlice {
				return false
			}
		case "cache":
			v2 := getFieldRdxVal(ctx, r.redisCli, c.fieldTwoVal, activity)
			inSlice := false
			for _, v := range v2 {
				if strings.ToLower(v1) == strings.ToLower(v) {
					inSlice = true
					break
				}
			}
			if !inSlice {
				return false
			}
		case "ldap":
			v2 := getFieldLDAPVal(ctx, r.redisCli, c.fieldTwoVal, activity)
			inSlice := false
			for _, v := range v2 {
				if strings.ToLower(v1) == strings.ToLower(v) {
					inSlice = true
					break
				}
			}
			if !inSlice {
				return false
			}
		default:
			logger.Warnf("invalid condition(fieldTwoTyp: %s), will ignore!", c.fieldTwoTyp)
			return false
		}
	} else {
		var v2 string
		if c.fieldTwoTyp == "const" {
			v2 = c.fieldTwoVal
		} else {
			if c.fieldTwoIdx < 0 || int(c.fieldTwoIdx) >= len(activity) {
				return false
			}
			v2 = getFieldVal(c.fieldTwoVal, activity[c.fieldTwoIdx])
		}

		if v1 == "" && v2 == "" {
			// 都为空时的合理性，也是存在的
			return true
		}
		if v1 == "" || v2 == "" {
			return false
		}
		if !compare(c.operation, v1, v2) {
			return false
		}
	}

	return true
}

func getFieldVal(field string, act flowActivity) string {
	// 根据字段名获取字段值
	fKey := fmt.Sprintf("field_%s", field)
	v, ok := act.activityCache[fKey]
	if !ok {
		return ""
	}

	return v
}

func getFieldRdxVal(ctx context.Context, redisCli *redis.Client, field2 string, acts []flowActivity) []string {
	// 从redis中获取key_xxxx($s1.TargetDomainName), 并转为string.Join(",")形式字符串
	// key_xxxx 可带参数，如: `key_ada:engine:user:%s:sensitive_users($s1.TargetDomainName)`，也可留空
	cacheKey, ok := buildCacheLookupKey(field2, acts)
	if !ok {
		logger.Warnf("invalid cache key template:%s", field2)
		return []string{}
	}

	items, err := redisCli.SMembers(ctx, cacheKey).Result()
	if err != nil {
		logger.Warnf("5-invalid condition(redis get field2: %s err:%v", field2, err)
		return []string{}
	}

	return items
}

func compare(op string, value1, value2 string) bool {
	switch op {
	case "==":
		return value1 == value2
	case "!=":
		return value1 != value2
	case "<":
		return value1 < value2
	case "<=":
		return value1 <= value2
	case ">":
		return value1 > value2
	case ">=":
		return value1 >= value2
	default:
		return false
	}
}
