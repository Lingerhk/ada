package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	utime "ada/infra/time"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"strconv"
	"strings"
	"time"
)

// 高级检索结构
type AdvancedSearchReq struct {
	Name  string
	Type  string
	Value []string
}

// fixme 需要优化该处，修改为通用方法
func initTimeInterval(startTm string, endTm string) (time.Time, time.Time, error) {
	startTime, err := time.Parse("2006-01-02 15:04:05", startTm)
	if err != nil {
		logger.Errorf("parse time err:%v", err)
		return time.Time{}, time.Time{}, err
	}
	endTime, err := time.Parse("2006-01-02 15:04:05", endTm)
	if err != nil {
		logger.Errorf("parse time err:%v", err)
		return time.Time{}, time.Time{}, err
	}

	//起止日期相同的话截止日期+1，前端没有传时分秒
	if startTm == endTm {
		endTime = endTime.AddDate(0, 0, 1)
	}
	return startTime, endTime.Add(time.Second).Add(time.Second), nil
}

func FindThreatEventLikePattern(e *config.Env, query bson.D, sortTm int32, limit, offset int32) ([]model.AlertEventESDB, int64, error) {
	var ae []model.AlertEventESDB
	tb := (&model.AlertEventESDB{}).CollectName()

	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	sort := bson.M{"end_ts": -1}
	if sortTm != 0 {
		sort["end_ts"] = sortTm
	}
	err = e.MongoCli.FindSortByLimitAndSkip(tb, query, sort, &ae, int64(limit), int64(offset))
	if err != nil {
		return nil, 0, err
	}

	return ae, total, nil
}

func ThreatEventFilter(threatIDList []string, levels []int32, eventStatus int32, startTm, endTm string) (bson.D, error) {
	query := bson.D{}
	if len(threatIDList) > 0 {
		query = append(query, bson.E{Key: "flow_id", Value: bson.D{{"$in", threatIDList}}})
	}
	if len(levels) > 0 {
		query = append(query, bson.E{Key: "level", Value: bson.D{{"$in", levels}}})
	}

	if eventStatus != -1 {
		query = append(query, bson.E{Key: "event_status", Value: eventStatus})
	}

	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, err
		}

		query = append(query, bson.E{Key: "end_ts", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8).UnixMilli(), "$lte": endTime.Add(-time.Hour * 8).UnixMilli()}})
	}

	return query, nil
}

// 等于 eq，不等于ne 之前lt，之后gt 两者之间bt，包含contain 不包含 not_contain
// todo 优化生成query的逻辑
func AdvancedSearch(request []AdvancedSearchReq) (bson.D, error) {
	query := bson.D{}
	for _, v := range request {
		if v.Name == "source" || v.Name == "target" {
			//var value string
			// 不包含
			if v.Type == "not_contain" {
				if v.Value[0] == "" {
					continue
				}
				//value = fmt.Sprintf("^((?!%s).)*$", v.Value[0])
				source := primitive.E{Key: "$and", Value: bson.A{
					bson.D{{fmt.Sprintf("field_data.%s_username", v.Name), bson.M{"$ne": v.Value[0]}}},
					bson.D{{fmt.Sprintf("field_data.%s_ip", v.Name), bson.M{"$ne": v.Value[0]}}},
					bson.D{{fmt.Sprintf("field_data.%s_machine_username", v.Name), bson.M{"$ne": v.Value[0]}}},
					bson.D{{fmt.Sprintf("field_data.%s_machine_hostname", v.Name), bson.M{"$ne": v.Value[0]}}},
					//bson.D{{fmt.Sprintf("field_data.%s_computer", v.Name), primitive.Regex{Pattern: value, Options: "i"}}},
					//bson.D{{fmt.Sprintf("field_data.%s_username", v.Name), primitive.Regex{Pattern: value, Options: "i"}}},
					//bson.D{{fmt.Sprintf("field_data.%s_ip", v.Name), primitive.Regex{Pattern: value, Options: "i"}}},
				}}
				query = append(query, source)
			} else {
				//value = v.Value[0]
				source := primitive.E{Key: "$or", Value: bson.A{
					bson.D{{fmt.Sprintf("field_data.%s_username", v.Name), v.Value[0]}},
					bson.D{{fmt.Sprintf("field_data.%s_ip", v.Name), v.Value[0]}},
					bson.D{{fmt.Sprintf("field_data.%s_machine_username", v.Name), v.Value[0]}},
					bson.D{{fmt.Sprintf("field_data.%s_machine_hostname", v.Name), v.Value[0]}},
				}}
				query = append(query, source)
			}

			continue
		}

		switch v.Type {
		case "eq":
			var valueList []int
			if v.Name == "risk_level" {
				for _, v := range v.Value {
					atoi, err := strconv.Atoi(v)
					if err != nil {
						continue
					}
					valueList = append(valueList, atoi)
				}
				query = append(query, bson.E{v.Name, bson.D{{"$in", valueList}}})
			} else {
				query = append(query, bson.E{v.Name, bson.D{{"$in", v.Value}}})
			}
		case "ne":
			var valueList []int
			if v.Name == "risk_level" {
				for _, v := range v.Value {
					atoi, err := strconv.Atoi(v)
					if err != nil {
						continue
					}
					valueList = append(valueList, atoi)
				}
				query = append(query, bson.E{v.Name, bson.D{{"$nin", valueList}}})
			} else {
				query = append(query, bson.E{v.Name, bson.D{{"$nin", v.Value}}})
			}
		case "lt":
			if v.Name == "end_tm" {
				tm, err := time.Parse("2006-01-02 15:04:05", v.Value[0])
				if err != nil {
					logger.Errorf("parse time err:%v", err)
					return nil, err
				}
				query = append(query, bson.E{v.Name, bson.D{{"$lte", tm.Add(-time.Hour * 8)}}})
			} else {
				query = append(query, bson.E{v.Name, bson.D{{"$lte", v.Value[0]}}})
			}
		case "gt":
			if v.Name == "end_tm" {
				tm, err := time.Parse("2006-01-02 15:04:05", v.Value[0])
				if err != nil {
					logger.Errorf("parse time err:%v", err)
					return nil, err
				}
				query = append(query, bson.E{v.Name, bson.D{{"$gte", tm.Add(-time.Hour * 8)}}})
			} else {
				query = append(query, bson.E{v.Name, bson.D{{"$gte", v.Value[0]}}})
			}

		case "bt":
			startTime, err := time.Parse("2006-01-02 15:04:05", v.Value[0])
			if err != nil {
				logger.Errorf("parse time err:%v", err)
				return nil, err
			}
			endTime, err := time.Parse("2006-01-02 15:04:05", v.Value[1])
			if err != nil {
				logger.Errorf("parse time err:%v", err)
				return nil, err
			}

			query = append(query, bson.E{v.Name, bson.D{{"$gte", startTime.Add(-time.Hour * 8)}}})
			query = append(query, bson.E{v.Name, bson.D{{"$lte", endTime.Add(-time.Hour * 8)}}})
		}
	}
	return query, nil
}

func GetThreatEventByID(e *config.Env, id string) (*model.AlertEventESDB, error) {
	ae := model.AlertEventESDB{}

	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.M{"_id": Id}
	err, _ = e.MongoCli.FindOne(ae.CollectName(), query, &ae)
	if err != nil {
		logger.Errorf("get threat event err:%v", err)
		return nil, err
	}

	return &ae, nil
}

func GetThreatDescByID(e *config.Env, flowId string) (*model.AlertDesc, error) {
	ad := model.AlertDesc{}

	err, _ := e.MongoCli.FindOne(ad.CollectName(), bson.M{"_id": flowId}, &ad)
	if err != nil {
		logger.Errorf("get threat desc err:%v", err)
		return nil, err
	}

	return &ad, nil
}

func GetAllThreatDesc(e *config.Env) ([]model.AlertDesc, error) {
	var adList []model.AlertDesc
	tb := (&model.AlertDesc{}).CollectName()

	query := bson.M{}
	err := e.MongoCli.FindAll(tb, query, &adList)
	if err != nil {
		return nil, err
	}
	return adList, nil
}

func FindThreatDescSelect(e *config.Env, levels []int32, enable []bool) ([]model.AlertDesc, error) {
	var adList []model.AlertDesc
	tb := (&model.AlertDesc{}).CollectName()

	query := bson.M{}
	if len(levels) > 0 {
		query = bson.M{"level": bson.M{"$in": levels}}
	}
	if len(enable) > 0 {
		query = bson.M{"enable": bson.M{"$in": enable}}
	}

	err := e.MongoCli.FindAll(tb, query, &adList)
	if err != nil {
		return nil, err
	}
	return adList, nil
}

func UpdateThreatDesc(e *config.Env, Id, typ string, switchVal bool) error {
	var ad model.AlertDesc

	query := bson.M{"_id": Id}

	update := bson.M{}
	if typ == "is_enable" {
		update = bson.M{"$set": bson.M{"enable": switchVal, "update_tm": utime.CurTime()}}
	} else if typ == "auto_block" {
		update = bson.M{"$set": bson.M{"auto_block": switchVal, "update_tm": utime.CurTime()}}
	}

	return e.MongoCli.UpdateRaw(ad.CollectName(), query, &update, false)
}

// GetThreatDescByID 需要优化该处，修改为通用方法
func GetThreatFlowByID(e *config.Env, flowId string, fieldData map[string]string) (*model.AttackFlow, error) {
	ad := model.AlertDesc{}
	err, _ := e.MongoCli.FindOne(ad.CollectName(), bson.M{"_id": flowId}, &ad)
	if err != nil {
		logger.Errorf("get threat desc err:%v", err)
		return nil, err
	}

	// 获取攻击流图: 根据tb_alert_desc表中AttackFlow的定义，从fieldData中获取对应的字段值
	var attackInfo = model.AttackFlow{
		Fields:  []map[string]string{},
		Relates: ad.AttackFlow.Relates,
	}

	for _, item := range ad.AttackFlow.Fields {
		f := make(map[string]string)
		obj, ok := item["obj"]
		if !ok {
			continue
		}
		f["obj"] = obj

		keys, ok := item["keys"]
		if !ok {
			continue
		}
		for _, key := range strings.Split(keys, ",") {
			extracted := false
			for fieldKey, fieldVal := range fieldData {
				if strings.HasSuffix(fieldKey, key) {
					// fieldKey格式: $s1.field_TargetUserName, 这里按field_截取
					parts := strings.Split(fieldKey, ".field_")
					if len(parts) != 2 {
						continue
					}

					extracted = true
					f["key"] = parts[1]
					f["value"] = fieldVal
					break
				}
			}
			if extracted {
				continue
			}
		}

		attackInfo.Fields = append(attackInfo.Fields, f)
	}

	return &attackInfo, nil
}

func UpdateThreatEventStatus(e *config.Env, id string, eventStatus int32, remark string) error {
	var ae model.AlertEventESDB

	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	query := bson.M{"_id": Id}
	update := bson.M{"event_status": eventStatus}
	if remark != "" {
		update["remark"] = remark
	}

	return e.MongoCli.Update(ae.CollectName(), query, update, false)
}

func GetThreatActivityByID(e *config.Env, id string) (*model.AlertActivityESDB, error) {
	aa := model.AlertActivityESDB{}
	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.M{"_id": Id}
	err, _ = e.MongoCli.FindOne(aa.CollectName(), query, &aa)
	if err != nil {
		logger.Errorf("get threat activity err:%v", err)
		return nil, err
	}

	return &aa, nil
}

func ThreatActivityFilter(levels []int32, dcHostnames, titles []string, startTm, endTm string) (bson.D, error) {
	query := bson.D{}
	if len(levels) > 0 {
		query = append(query, bson.E{Key: "level", Value: bson.D{{"$in", levels}}})
	}

	if len(dcHostnames) > 0 {
		query = append(query, bson.E{Key: "dc_hostname", Value: bson.D{{"$in", dcHostnames}}})
	}

	if len(titles) > 0 {
		query = append(query, bson.E{Key: "title", Value: bson.D{{"$in", titles}}})
	}

	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, err
		}

		query = append(query, bson.E{Key: "create_tm", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8)}})
	}

	return query, nil
}

func FindThreatActivitySelect(e *config.Env, query bson.D, sortTm int32, limit, offset int32) ([]model.AlertActivityESDB, int64, error) {
	var aas []model.AlertActivityESDB
	tb := (&model.AlertActivityESDB{}).CollectName()

	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	sort := bson.M{"create_tm": -1}
	if sortTm != 0 {
		sort["create_tm"] = sortTm
	}
	err = e.MongoCli.FindSortByLimitAndSkip(tb, query, sort, &aas, int64(limit), int64(offset))
	if err != nil {
		return nil, 0, err
	}

	return aas, total, nil
}

func GetThreatActivityAggNames(e *config.Env, dcHostname []string, startTm, endTm string) (map[string]int32, error) {
	tb := (&model.AlertActivityESDB{}).CollectName()

	var matchStage bson.D
	if len(dcHostname) > 0 {
		matchStage = append(matchStage, bson.E{Key: "dc_hostname", Value: bson.D{{"$in", dcHostname}}})
	}

	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, err
		}
		//起止日期相同的话截止日期+1，前端没有传时分秒
		if startTm == endTm {
			endTime = endTime.Add(1 * time.Second)
		}
		matchStage = append(matchStage, bson.E{"timestamp", bson.M{"$gte": startTime.UnixMilli(), "$lte": endTime.UnixMilli()}})
	} else {
		matchStage = append(matchStage, bson.E{"timestamp", bson.M{"$gte": 1645539742222}})
	}

	pipeline := mongo.Pipeline{
		{{"$match", matchStage}},
		{{"$group", bson.D{
			{"_id", "$title"},
			{"count", bson.D{{"$sum", 1}}},
		}}},
		{{"$sort", bson.D{{"count", -1}}}},
		{{"$limit", 2000}}, // 限制2000条,足够了
	}

	var results []bson.M
	err := e.MongoCli.FindWithAggregation(tb, pipeline, &results)
	if err != nil {
		logger.Errorf("threat tops err:%v", err)
		return nil, err
	}

	aggNames := make(map[string]int32)
	for _, item := range results {
		aggNames[item["_id"].(string)] = item["count"].(int32)

	}

	return aggNames, nil
}

func FindSensitiveEntryList(e *config.Env, typ string, domains []string, origins []int32, startTm, endTm string, orderCreateTm, orderUpdateTm, limit, offset int32) ([]model.SensitiveEntry, int64, error) {
	var se []model.SensitiveEntry
	tb := (&model.SensitiveEntry{}).CollectName()
	query := bson.M{"type": typ}

	if len(domains) > 0 {
		query["domain"] = bson.M{"$in": domains}
	}
	if len(origins) > 0 {
		query["origin"] = bson.M{"$in": origins}
	}
	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, 0, err
		}
		//起止日期相同的话截止日期+1，前端没有传时分秒
		if startTm == endTm {
			endTime = endTime.AddDate(0, 0, 1)
		}
		query["create_tm"] = bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8).Add(time.Second)}
	}

	sort := bson.M{}
	if orderCreateTm != 0 {
		sort["create_tm"] = orderCreateTm
	}
	if orderUpdateTm != 0 {
		sort["update_tm"] = orderUpdateTm
	}

	count, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	err = e.MongoCli.FindSortByLimitAndSkip(tb, query, sort, &se, int64(limit), int64(offset))
	if err != nil {
		return nil, 0, err
	}

	return se, count, nil
}

func GetSensitiveEntryById(e *config.Env, id string) (*model.SensitiveEntry, error) {
	se := model.SensitiveEntry{}
	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.M{"_id": Id}
	err, _ = e.MongoCli.FindOne(se.CollectName(), query, &se)
	if err != nil {
		logger.Errorf("get threat activity err:%v", err)
		return nil, err
	}

	return &se, nil
}

func GetSensitiveEntryByName(e *config.Env, name, typ, domain string) (*model.SensitiveEntry, error) {
	se := model.SensitiveEntry{}
	query := bson.M{"type": typ, "domain": domain, "content.name": name}
	err, _ := e.MongoCli.FindOne(se.CollectName(), query, &se)
	if err != nil {
		logger.Errorf("get sensitive entry err:%v", err)
		return nil, err
	}

	return &se, nil
}

func AddSensitiveEntry(e *config.Env, name, sid, typ, domain string) error {
	var se model.SensitiveEntry

	se.Origin = 1 // 手动
	se.Domain = domain
	se.Type = typ
	se.Content = map[string]string{"name": name, "sid": sid}
	se.CreateTm = utime.CurTime()
	se.UpdateTm = utime.CurTime()

	return e.MongoCli.Insert(se.CollectName(), &se)
}

func DeleteSensitiveEntry(e *config.Env, Id string) error {
	var se model.SensitiveEntry

	objId, err := primitive.ObjectIDFromHex(Id)
	if err != nil {
		return err
	}

	return e.MongoCli.RemoveById(se.CollectName(), objId)
}

func ThreatTops(e *config.Env, domain, typ string, duration int32) ([]bson.M, error) {
	if duration == 0 {
		duration = 7
	}

	var matchStage bson.D
	if domain != "all" {
		matchStage = append(matchStage, bson.E{"dc_hostname", bson.M{"$regex": primitive.Regex{Pattern: ".*" + domain + "$", Options: "i"}}})
	}

	startTimestamp := time.Now().UnixNano()/int64(time.Millisecond) - int64(duration)*24*3600*1000

	var tb string
	var pipeline mongo.Pipeline
	if typ == "activity" {
		// 活动威胁top
		tb = (&model.AlertActivityESDB{}).CollectName()
		matchStage = append(matchStage, bson.E{"timestamp", bson.M{"$gte": startTimestamp}})

		pipeline = mongo.Pipeline{
			{{"$match", matchStage}},
			{{"$group", bson.D{
				{"_id", "$title"},
				{"count", bson.D{{"$sum", 1}}},
			}}},
			{{"$sort", bson.D{{"count", -1}}}},
			{{"$limit", 10}},
		}
	} else {
		// 事件威胁top
		tb = (&model.AlertEventESDB{}).CollectName()
		matchStage = append(matchStage, bson.E{"start_ts", bson.M{"$gte": startTimestamp}})

		pipeline = mongo.Pipeline{
			{{"$match", matchStage}},
			{{"$group", bson.D{
				{"_id", "$title"},
				{"count", bson.D{{"$sum", 1}}},
			}}},
			{{"$sort", bson.D{{"count", -1}}}},
			{{"$limit", 10}},
		}
	}

	var results []bson.M
	err := e.MongoCli.FindWithAggregation(tb, pipeline, &results)
	if err != nil {
		logger.Errorf("threat tops err:%v", err)
		return nil, err
	}

	return results, nil
}

func ThreatTrends(e *config.Env, domain string, levels []int32, duration int32) ([]bson.M, error) {
	if duration == 0 {
		duration = 7
	}
	startTimestamp := time.Now().UnixNano()/int64(time.Millisecond) - int64(duration)*24*3600*1000

	matchStage := bson.D{
		{"timestamp", bson.M{"$gte": startTimestamp}},
	}

	if domain != "all" {
		matchStage = append(matchStage, bson.E{"dc_hostname", bson.M{"$regex": primitive.Regex{Pattern: ".*" + domain + "$", Options: "i"}}})
	}

	if len(levels) > 0 {
		matchStage = append(matchStage, bson.E{"level", bson.M{"$in": levels}})
	}

	tb := (&model.AlertActivityESDB{}).CollectName()
	pipeline := mongo.Pipeline{
		{{"$match", matchStage}},
		{{"$group", bson.D{
			{"_id", bson.M{
				"$subtract": []interface{}{
					"$timestamp",
					bson.M{"$mod": []interface{}{"$timestamp", duration * 60 * 60 * 1000}},
				},
			}},
			{"count", bson.D{{"$sum", 1}}},
		}}},
		{{"$sort", bson.D{{"_id", 1}}}},
	}

	var results []bson.M
	err := e.MongoCli.FindWithAggregation(tb, pipeline, &results)
	if err != nil {
		logger.Errorf("threat trends err:%v", err)
		return nil, err
	}

	return results, nil
}

func FindAllThreatWhitelist(e *config.Env, ruleId string, domains []string, origins []int32, search, startTm, endTm string, orderUpdateTm int32, limit, skip int64) ([]model.AlertWhitelist, int64, error) {
	var awList []model.AlertWhitelist
	tb := (&model.AlertWhitelist{}).CollectName()

	query := bson.D{}
	if ruleId != "" { // 只查询ruleId对应的白名单
		query = append(query, bson.E{Key: "rule_id", Value: ruleId})
	} else {
		if len(domains) > 0 {
			query = append(query, bson.E{Key: "domain", Value: bson.M{"$in": domains}})
		}

		if len(origins) > 0 {
			query = append(query, bson.E{Key: "origin", Value: bson.M{"$in": origins}})
		}

		if search != "" {
			query = append(query, bson.E{Key: "rule_name", Value: bson.M{"$regex": search, "$options": "i"}})
		}

		if startTm != "" && endTm != "" {
			startTime, endTime, err := initTimeInterval(startTm, endTm)
			if err != nil {
				return nil, 0, err
			}

			query = append(query, bson.E{Key: "update_tm", Value: bson.M{"$gte": startTime, "$lte": endTime}})
		}
	}

	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}
	if err := e.MongoCli.FindByLimitAndSkip(tb, query, &awList, limit, skip); err != nil {
		return nil, 0, err
	}
	return awList, total, nil
}

func GetThreatWhitelistById(e *config.Env, wId string) (*model.AlertWhitelist, error) {
	var aw model.AlertWhitelist

	Id, err := primitive.ObjectIDFromHex(wId)
	if err != nil {
		return nil, err
	}
	err, exist := e.MongoCli.FindOne(aw.CollectName(), bson.M{"_id": Id}, &aw)
	if err != nil || !exist {
		return nil, err
	}

	return &aw, nil
}

func AddThreatWhitelist(e *config.Env, ruleId, ruleTitle, ruleType, domain, remark string, origin int32, rules []map[string]string) (string, error) {
	var aw model.AlertWhitelist

	aw.ID = primitive.NewObjectID()
	aw.RuleId = ruleId
	aw.RuleName = ruleTitle
	aw.RuleType = ruleType
	aw.RuleInfo = rules
	aw.Domain = domain
	aw.Origin = origin
	aw.Remark = remark
	aw.CreateTm = utime.CurTime()
	aw.UpdateTm = utime.CurTime()

	err := e.MongoCli.Insert(aw.CollectName(), &aw)
	if err != nil {
		return "", err
	}
	return aw.ID.Hex(), nil
}

func UpdateThreatWhitelist(e *config.Env, Id, remark string, rules []map[string]string) error {
	var sc model.AlertWhitelist

	id, err := primitive.ObjectIDFromHex(Id)
	if err != nil {
		return err
	}

	query := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{"rule_info": rules, "remark": remark, "update_tm": utime.CurTime()}}
	err = e.MongoCli.UpdateRaw(sc.CollectName(), query, &update, false)
	if err != nil {
		return err
	}
	return nil
}

func DeleteThreatWhitelist(e *config.Env, Id string) error {
	var aw model.AlertWhitelist

	objId, err := primitive.ObjectIDFromHex(Id)
	if err != nil {
		return err
	}

	err = e.MongoCli.RemoveById(aw.CollectName(), objId)
	if err != nil {
		return err
	}

	return nil
}

func FindDomainEntryUser(e *config.Env, domain, search string) ([]string, error) {
	var auList []model.AssetUser
	tb := (&model.AssetUser{}).CollectName()

	query := bson.M{"domain": domain}
	if search != "" {
		query["sAMAccountName"] = bson.M{"$regex": search, "$options": "i"}
	}
	err := e.MongoCli.FindAll(tb, query, &auList)
	if err != nil {
		return nil, err
	}

	var users []string
	for _, item := range auList {
		if item.IsDelete == true {
			continue
		}
		users = append(users, item.SAMAccountName)
	}

	return users, nil
}

func FindDomainEntryGroup(e *config.Env, domain, search string) ([]string, error) {
	var agList []model.AssetGroup
	tb := (&model.AssetGroup{}).CollectName()

	query := bson.M{"domain": domain}
	if search != "" {
		query["sAMAccountName"] = bson.M{"$regex": search, "$options": "i"}
	}
	err := e.MongoCli.FindAll(tb, query, &agList)
	if err != nil {
		return nil, err
	}

	var users []string
	for _, item := range agList {
		if item.IsDelete == true {
			continue
		}
		users = append(users, item.SAMAccountName)
	}

	return users, nil
}

func FindDomainEntryComputer(e *config.Env, domain, search string) ([]string, error) {
	var auList []model.AssetUser
	tb := (&model.AssetUser{}).CollectName()

	query := bson.M{"domain": domain}
	if search != "" {
		query["sAMAccountName"] = bson.M{"$regex": search, "$options": "i"}
	}
	err := e.MongoCli.FindAll(tb, query, &auList)
	if err != nil {
		return nil, err
	}

	var users []string
	for _, item := range auList {
		if item.IsDelete == true {
			continue
		}
		users = append(users, item.SAMAccountName)
	}

	return users, nil
}

// 威胁阻断策略
func FindAllThreatBlock(e *config.Env, domains []string, origin []int32, search, startTm, endTm string, limit, skip int64) ([]model.AlertBlock, int64, error) {
	var abList []model.AlertBlock
	tb := (&model.AlertBlock{}).CollectName()

	query := bson.D{}
	if len(domains) > 0 {
		query = append(query, bson.E{Key: "domain", Value: bson.M{"$in": domains}})
	}

	if len(origin) > 0 {
		query = append(query, bson.E{Key: "origin", Value: bson.M{"$in": origin}})
	}

	if search != "" {
		// TODO: fixme
		query = append(query, bson.E{Key: "user_list", Value: bson.M{"$regex": search, "$options": "i"}})
	}

	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, 0, err
		}
		query = append(query, bson.E{Key: "update_tm", Value: bson.M{"$gte": startTime, "$lte": endTime}})
	}

	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}
	if err := e.MongoCli.FindByLimitAndSkip(tb, query, &abList, limit, skip); err != nil {
		return nil, 0, err
	}
	return abList, total, nil
}

func AddThreatBlock(e *config.Env, name, domain, remark string, userBlock, ipBlock bool, userList, ipList []string, result []map[string]string) error {
	var ab model.AlertBlock

	ab.ID = primitive.NewObjectID()
	ab.Name = name
	ab.Domain = domain
	ab.Origin = 1 // 手动
	ab.UserBlock = userBlock
	ab.IpBlock = ipBlock
	ab.UserList = userList
	ab.IpList = ipList
	ab.Result = result
	ab.Remark = remark
	ab.CreateTm = utime.CurTime()
	ab.UpdateTm = utime.CurTime()

	return e.MongoCli.Insert(ab.CollectName(), &ab)
}

func UpdateThreatBlock(e *config.Env, id, name, remark string, userBlock, ipBlock bool, userList, ipList []string, results []map[string]string) error {
	var ab model.AlertBlock

	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	query := bson.M{"_id": Id}
	updatePrams := bson.M{"user_block": userBlock, "ip_block": ipBlock, "update_tm": utime.CurTime()}
	if name != "" {
		updatePrams["name"] = name
	}
	if len(userList) > 0 {
		updatePrams["user_list"] = userList
	}
	if len(ipList) > 0 {
		updatePrams["ip_list"] = ipList
	}
	if remark != "" {
		updatePrams["remark"] = remark
	}

	update := bson.M{"$set": updatePrams}
	return e.MongoCli.UpdateRaw(ab.CollectName(), query, &update, false)
}

func DeleteThreatBlock(e *config.Env, id string) error {
	var ab model.AlertBlock

	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	return e.MongoCli.RemoveById(ab.CollectName(), objId)
}

func GetThreatBlock(e *config.Env, id string) (*model.AlertBlock, error) {
	var ab model.AlertBlock

	objId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	err, exist := e.MongoCli.FindOne(ab.CollectName(), bson.M{"_id": objId}, &ab)
	if err != nil || !exist {
		return nil, err
	}
	return &ab, nil
}
