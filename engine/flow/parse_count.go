package flow

import (
	"ada/engine/common"
	"ada/engine/model"
	"ada/infra/base"
	"context"
	"encoding/json"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// 匹配器: count类型
func (r *Ruleset) matchEventCount(ctx context.Context, fr FlowRule, flowInstances []string) {
	for _, insId := range flowInstances {
		logger.Debugf("11----handle EventTypeCount instance_id %s", insId)

		stop := time.Now().UnixNano() / 1e6

		// 取最新winSize内的所有事件
		activities, err := r.getFlowActivitiesByWinSize(ctx, insId, fr.Detection.WinSizeTs, stop)
		if err != nil {
			logger.Warnf("get flow events by win_size err:%v, will ignore this event!", err)
			continue
		}

		logger.Debugf("22----handle EventTypeCount activities %#v", activities)

		// match_by: "$s1._count == 3"
		matchBy := fr.Detection.MatchBy
		_, v, err := parseExpression(matchBy)
		if err != nil {
			logger.Warnf("parse matchBy err:%v, will ignore this flow instance!", err)
			continue
		}

		if len(activities) >= v {
			// count超过阈值，生成告警（多）事件
			if err := r.storeEvent(ctx, insId, fr, activities); err != nil {
				logger.Warnf("store event(multi-count) err:%v, will ignore this flow event!", err)
			}

			// 将该flow instance中的activity从redis(zset)删除，start从new开始算(ts<now的删除)
			err := r.redisCli.ZRemRangeByScore(ctx, insId, strconv.FormatInt(stop-common.MaxFlowWinSize, 10), strconv.FormatInt(stop, 10)).Err()
			if err != nil {
				logger.Warnf("delete alerted event from zset err:%v", err)
			}
			continue
		}
	}
}

func (r *Ruleset) storeEvent(ctx context.Context, insId string, fr FlowRule, activities []flowActivity) error {
	dcHostname := activities[0].activityCache["dc_hostname"]

	if wId, ignored := r.whitelistFilter(ctx, fr, activities, dcHostname); ignored == true {
		logger.Infof("flow event(%s) filter by whitelist(%s), will ignore!", fr.ID, wId)
		return nil
	}

	// insId format: flow-xxxx-xxxx-xxxx-xxxx_uniqueId
	parts := strings.SplitN(insId, "_", 2)
	if len(parts) != 2 {
		logger.Errorf("invalid flow instance id:%s, will ignore!", insId)
		return nil
	}
	uniqueId := parts[1]

	var activityIds []string
	var fields = make(map[string]string)

	minTs := activities[0].timestamp
	maxTs := activities[0].timestamp
	for idx, activity := range activities {
		activityIds = append(activityIds, activity.activityCache["mid"])
		// 将每个activity中的field提取并更新到总的fields map中
		for fk, fv := range activity.activityCache {
			k := fmt.Sprintf("$s%d.%s", idx+1, fk)
			fields[k] = fv
		}

		if activity.timestamp > maxTs {
			maxTs = activity.timestamp
		}
		if activity.timestamp < minTs {
			minTs = activity.timestamp
		}
	}

	// 向AlertEventESDB表插入数据
	aet := model.AlertEventESDB{
		ID:          bson.NewObjectID(),
		Title:       fr.Title,
		Desc:        fr.Description,
		FlowId:      fr.ID,
		UniqueId:    uniqueId,
		AttCkId:     fr.Tags[0],
		Level:       common.GetRiskLevel(fr.Level),
		Status:      fr.Status,
		EventStatus: 0,
		Tags:        fr.Tags,
		DcHostname:  dcHostname,
		ActivityIds: activityIds,
		FieldData:   fields,
		Result:      "-",
		Remark:      "", // portal侧更新
		CreateTm:    time.Now(),
		StartTs:     minTs,
		EndTs:       maxTs,
	}

	// 插入单条行为
	if err := r.mongoCli.Insert(aet.CollectName(), aet); err != nil {
		logger.Errorf("insert event err:%v", err)
		return err
	}

	// 将该事件发送到notify队列
	params := activities[0].activityCache
	params["eid"] = aet.ID.Hex()
	params["rule_id"] = fr.ID
	params["level"] = strconv.FormatInt(int64(common.GetRiskLevel(fr.Level)), 10)
	params["start_tm"] = strconv.FormatInt(minTs, 10)
	params["end_tm"] = strconv.FormatInt(maxTs, 10)
	if err := r.pushNotify(ctx, fr, params); err != nil {
		logger.Warnf("push event(multi-count) notify err:%v, will ignore this flow event!", err)
	}

	return nil
}

// whitelistFilter 白名单过滤
func (r *Ruleset) whitelistFilter(ctx context.Context, fr FlowRule, activities []flowActivity, dcHostname string) (string, bool) {
	// get all whitelist from redis, key: flow_whitelist:rule_id, val(hash): [{field:whitelist_id, value:condition},...]

	whiteKey := fmt.Sprintf("%s:%s", common.FlowWhitelistPrefixKey, fr.ID)
	whitelists, err := r.redisCli.HGetAll(ctx, whiteKey).Result()
	if err != nil {
		logger.Errorf("get whitelist from redis err:%v, will bypass whitelist!", err)
		return "", false
	}

	for wId, item := range whitelists {
		// conditions: china.com||condition1|[AND]|condition2|[AND]|condition3, each condition struct:field,op,value
		parts := strings.SplitN(item, "||", 2)
		if len(parts) != 2 {
			logger.Warnf("whitelist(%s) contain invalid item(%s), will ignore!", wId, item)
			continue
		}
		if strings.HasSuffix(strings.ToLower(dcHostname), parts[0]) == false {
			continue
		}

		conditions := strings.Split(parts[1], "|[AND]|")
		if len(conditions) == 0 {
			continue
		}

		// 目前仅支持AND条件, 后期优化进行语法解析，支持复杂表达式
		matched := true
		for _, condition := range conditions {
			parts := strings.SplitN(condition, ",", 3)
			if len(parts) != 3 {
				logger.Warnf("whitelist(%s) contain invalid condition(%s), will ignore!", wId, condition)
				continue
			}

			if whitelistCompare(parts[1], parts[0], parts[2], activities) == false {
				matched = false
				break
			}
		}
		if matched {
			return "", true
		}
	}

	return "", false
}

func (r *Ruleset) pushNotify(ctx context.Context, fr FlowRule, params map[string]string) error {
	type notifyInfo struct {
		Title     string            `json:"title"`
		MsgType   string            `json:"msg_type"`
		EventType string            `json:"event_type"`
		Desc      string            `json:"desc"`
		Params    map[string]string `json:"params"`
		Timestamp int64             `json:"timestamp"`
	}

	var notify = notifyInfo{
		Title:     fr.Title,
		MsgType:   "alert", // 对于threat event，参数:alert
		EventType: fr.Tags[0],
		Desc:      fr.Description,
		Params:    params,
		Timestamp: time.Now().Unix(),
	}

	notifyByte, _ := json.Marshal(notify)
	return r.redisCli.LPush(ctx, common.AlertNotifyQueueKey, notifyByte).Err()
}

func parseExpression(s string) (string, int, error) {
	// "$s1._count == 3"
	re := regexp.MustCompile(`\$(\w+\.\w+)\s*==\s*(\w+)`)
	matches := re.FindStringSubmatch(s)
	if len(matches) != 3 {
		return "", 0, fmt.Errorf("parse err %s", s)
	}

	i64, err := strconv.ParseInt(matches[2], 10, 64)
	if err != nil {
		return matches[1], 0, err
	}

	return matches[1], int(i64), nil
}

// whitelistCompare 白名单比较，支持: ==, !=, <, <=, >, >=, in, not_in, contain, not_contain, regex
func whitelistCompare(op string, field, value string, activities []flowActivity) bool {
	var fieldVals []string // 同一个field，在所有的activities中的值
	for _, activity := range activities {
		fieldVal := getFieldVal(field, activity)
		if fieldVal != "" {
			fieldVals = append(fieldVals, fieldVal)
		}
	}
	if len(fieldVals) == 0 {
		logger.Debugf("get field(%s) value from all activities failed,will ignore!", field)
		return false
	}

	switch op {
	case "==": // `==` 所有activities中，只有有一个field值等于value就行
		matched := false
		for _, val := range fieldVals {
			if val == value {
				matched = true
				break
			}
		}
		return matched
	case "!=": // `!=` 必须确保所有activities中的field值都不等于value
		matched := true
		for _, val := range fieldVals {
			if val == value {
				matched = false
				break
			}
		}
		return matched
	case "<": // `<` 必须确保所有activities中的field值都小于value
		matched := true
		for _, val := range fieldVals {
			if val >= value {
				matched = false
				break
			}
		}
		return matched
	case "<=": // `<=` 必须确保所有activities中的field值都小于等于value
		matched := true
		for _, val := range fieldVals {
			if val > value {
				matched = false
				break
			}
		}
		return matched
	case ">": // `>` 必须确保所有activities中的field值都大于value
		matched := true
		for _, val := range fieldVals {
			if val <= value {
				matched = false
				break
			}
		}
		return matched
	case ">=": // `>=` 必须确保所有activities中的field值都大于等于value
		matched := true
		for _, val := range fieldVals {
			if val < value {
				matched = false
				break
			}
		}
		return matched
	case "in": // `in` 必须确保所有activities中的field值都在value中, value:val1,val2,val3
		matched := true
		for _, val := range fieldVals {
			if val < value {
				matched = false
				break
			}
		}
		return matched
	case "not_in": // `not_in` 必须确保所有activities中的field值都不在value中
		values := strings.Split(value, ",")
		matched := true
		for _, val := range fieldVals {
			if base.InArray(val, values) {
				matched = false
				break
			}
		}
		return matched
	case "contain": // `contain` 只需要activities中有一个field值包含value
		matched := false
		for _, val := range fieldVals {
			if strings.Contains(val, value) {
				matched = true
				break
			}
		}
		return matched
	case "not_contain": // `not_contain` 必须确保所有activities中的field值都不包含value
		matched := true
		for _, val := range fieldVals {
			if strings.Contains(val, value) {
				matched = false
				break
			}
		}
		return matched
	case "regex": // `regex` 只需要activities中有一个field值包含value
		re, err := regexp.Compile(value)
		if err != nil {
			logger.Warnf("regex(%s) compile err:%v, will ignore!", value, err)
			return false
		}
		matched := false
		for _, val := range fieldVals {
			if re.MatchString(val) == true {
				matched = true
				break
			}
		}
		return matched
	default:
		logger.Warnf("invalid whitelist op(%s), will ignore!", op)
	}

	return false
}
