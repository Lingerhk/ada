package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	utime "ada/infra/time"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const domainUserHashCollection = "tb_domain_user_hash"

func GetLatestTaskByType(e *config.Env, typ string) (*model.ScanTasks, error) {
	var st []model.ScanTasks
	tb := (&model.ScanTasks{}).CollectName()

	query := bson.M{"type": typ, "status": "FINISH"}
	sort := bson.M{"create_tm": -1}
	err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &st, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(st) == 0 {
		return nil, nil
	}

	return &st[0], err
}

func FindBaselineListSelect(e *config.Env, groupId string, domains, subTypes []string, levels, results []int32, search string, orderUpdateTm, limit, offset int32) ([]model.ScanSubTasks, int64, error) {
	var sst []model.ScanSubTasks
	tb := (&model.ScanSubTasks{}).CollectName()

	query := bson.D{}
	query = append(query, bson.E{Key: "group_id", Value: groupId})
	if len(domains) > 0 {
		query = append(query, bson.E{Key: "params.domain", Value: bson.D{{Key: "$in", Value: domains}}})
	}
	if len(subTypes) > 0 {
		query = append(query, bson.E{Key: "result.plugin.type", Value: bson.D{{Key: "$in", Value: subTypes}}})
	}
	if len(levels) > 0 {
		query = append(query, bson.E{Key: "result.plugin.risk_level", Value: bson.D{{Key: "$in", Value: levels}}})
	}
	if len(results) > 0 {
		query = append(query, bson.E{Key: "result.status", Value: bson.D{{Key: "$in", Value: results}}})
	}
	if search != "" {
		query = append(query, bson.E{Key: "result.plugin.display", Value: bson.M{"$regex": escaping(search), "$options": "i"}})
	}

	sort := bson.M{"update_tm": -1}
	if orderUpdateTm != 0 {
		sort = bson.M{"update_tm": orderUpdateTm}
	}

	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}

	err = e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &sst, int64(limit), int64(offset))
	if err != nil {
		return sst, 0, err
	}

	return sst, total, nil
}

func FindWeakPwdListSelect(e *config.Env, groupId string, domains []string) ([]model.ScanSubTasks, error) {
	var sst []model.ScanSubTasks
	tb := (&model.ScanSubTasks{}).CollectName()

	query := bson.D{}
	query = append(query, bson.E{Key: "group_id", Value: groupId})
	if len(domains) > 0 {
		query = append(query, bson.E{Key: "params.domain", Value: bson.D{{Key: "$in", Value: domains}}})
	}

	sort := bson.M{"update_tm": -1}
	err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &sst, 0, 0)
	if err != nil {
		return sst, err
	}

	return sst, nil
}

func FindLeakListSelect(e *config.Env, groupId string, domains, subTypes []string, levels, results []int32, search, startTm, endTm string, orderUpdateTm, limit, offset int32) ([]model.ScanSubTasks, int64, error) {
	var sst []model.ScanSubTasks
	tb := (&model.ScanSubTasks{}).CollectName()

	query := bson.D{}
	query = append(query, bson.E{Key: "group_id", Value: groupId})
	if len(domains) > 0 {
		query = append(query, bson.E{Key: "params.domain", Value: bson.D{{Key: "$in", Value: domains}}})
	}
	if len(subTypes) > 0 {
		query = append(query, bson.E{Key: "result.plugin.type", Value: bson.D{{Key: "$in", Value: subTypes}}})
	}
	if len(levels) > 0 {
		query = append(query, bson.E{Key: "result.plugin.risk_level", Value: bson.D{{Key: "$in", Value: levels}}})
	}
	if len(results) > 0 {
		query = append(query, bson.E{Key: "result.status", Value: bson.D{{Key: "$in", Value: results}}})
	}
	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, 0, err
		}
		query = append(query, bson.E{Key: "update_tm", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8)}})
	}
	if search != "" {
		query = append(query, bson.E{Key: "result.plugin.name", Value: bson.M{"$regex": escaping(search), "$options": "i"}})
	}

	sort := bson.M{"update_tm": -1}
	if orderUpdateTm != 0 {
		sort = bson.M{"update_tm": orderUpdateTm}
	}

	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}

	err = e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &sst, int64(limit), int64(offset))
	if err != nil {
		return sst, 0, err
	}

	return sst, total, nil
}

func GetScanSubTaskById(e *config.Env, id string) (*model.ScanSubTasks, error) {
	sst := model.ScanSubTasks{}
	Id, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.M{"_id": Id}
	err, _ = e.MongoCli.FindOne(e.MongoContext(), sst.CollectName(), query, &sst)
	if err != nil {
		logger.Errorf("get scan sub_task err:%v", err)
		return nil, err
	}

	return &sst, err
}

func FindScanTasksSelect(e *config.Env, typ, status, cycle, startTm, endTm string, orderCreateTm, orderUpdateTm, limit, offset int32) ([]model.ScanTasks, int64, error) {
	var sts []model.ScanTasks
	tb := (&model.ScanTasks{}).CollectName()

	query := bson.D{}
	if typ != "all" {
		query = append(query, bson.E{Key: "type", Value: typ})
	}
	if status != "all" {
		query = append(query, bson.E{Key: "status", Value: status})
	}
	if cycle != "all" {
		query = append(query, bson.E{Key: "trigger", Value: cycle})
	}
	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, 0, err
		}
		query = append(query, bson.E{Key: "update_tm", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8)}})
	}

	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}

	sort := bson.M{"create_tm": -1}
	if orderCreateTm != 0 {
		sort["create_tm"] = orderCreateTm
	}
	if orderUpdateTm != 0 {
		sort["update_tm"] = orderUpdateTm
	}
	err = e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &sts, int64(limit), int64(offset))
	if err != nil {
		return nil, 0, err
	}

	return sts, total, nil
}

func GetScanTasksById(e *config.Env, id string) (*model.ScanTasks, error) {
	st := model.ScanTasks{}
	Id, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.M{"_id": Id}
	err, _ = e.MongoCli.FindOne(e.MongoContext(), st.CollectName(), query, &st)
	if err != nil {
		logger.Errorf("get scan task err:%v", err)
		return nil, err
	}

	return &st, err
}

func DeleteScanTasks(e *config.Env, Id string) error {
	// delete the related subtasks first
	var sst model.ScanSubTasks
	query := bson.M{"group_id": Id}
	err := e.MongoCli.Remove(e.MongoContext(), sst.CollectName(), &query, true)
	if err != nil {
		return err
	}

	st := model.ScanTasks{}
	objId, err := bson.ObjectIDFromHex(Id)
	if err != nil {
		return err
	}
	return e.MongoCli.RemoveById(e.MongoContext(), st.CollectName(), objId)
}

func FindSubScanTasks(e *config.Env, groupId string, limit, offset int32) ([]model.ScanSubTasks, int64, error) {
	var sst []model.ScanSubTasks
	tb := (&model.ScanSubTasks{}).CollectName()

	query := bson.M{"group_id": groupId}
	sort := bson.M{"create_tm": -1}

	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}

	err = e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &sst, int64(limit), int64(offset))
	if err != nil {
		return sst, 0, err
	}

	return sst, total, nil
}

func DeleteDomainUserHash(e *config.Env, domain string) error {
	return e.MongoCli.Remove(e.MongoContext(), domainUserHashCollection, bson.M{"domain": domain}, true)
}

func GetLatestSubTaskByDomain(e *config.Env, domain, typ string) ([]model.ScanSubTasks, error) {
	var st []model.ScanTasks
	tb := (&model.ScanTasks{}).CollectName()

	query := bson.D{
		{Key: "type", Value: typ},
		{Key: "status", Value: "FINISH"},
		{Key: "domain", Value: domain},
	}

	sort := bson.M{"create_tm": -1}
	err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &st, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(st) == 0 {
		return nil, nil
	}

	var sst []model.ScanSubTasks
	tb2 := (&model.ScanSubTasks{}).CollectName()
	query2 := bson.D{}
	query2 = append(query2, bson.E{Key: "status", Value: "FINISH"}, bson.E{Key: "group_id", Value: st[0].ID.Hex()}, bson.E{Key: "params.domain", Value: domain})
	sort2 := bson.M{"update_tm": -1}
	err = e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb2, query2, sort2, &sst, 500, 0)
	if err != nil {
		return sst, err
	}

	return sst, nil
}

func FindAllScanConf(e *config.Env) ([]model.ScanConf, error) {
	var sc []model.ScanConf
	tb := (&model.ScanConf{}).CollectName()

	err := e.MongoCli.FindAll(e.MongoContext(), tb, bson.M{}, &sc)
	if err != nil {
		return nil, err
	}

	return sc, err
}

func FindScanTmplSelect(e *config.Env, typ string, limit, offset int64) ([]model.ScanTemplate, int64, error) {
	var st []model.ScanTemplate
	tb := (&model.ScanTemplate{}).CollectName()

	query := bson.M{}
	if typ != "all" {
		query["type"] = typ
	}

	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}

	sort := bson.M{"update_tm": -1}
	if err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &st, limit, offset); err != nil {
		return nil, 0, err
	}

	return st, total, nil
}

func GetScanTmplById(e *config.Env, id string) (*model.ScanTemplate, error) {
	st := model.ScanTemplate{}
	Id, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.M{"_id": Id}
	err, _ = e.MongoCli.FindOne(e.MongoContext(), st.CollectName(), query, &st)
	if err != nil {
		logger.Errorf("get scan tmpl err:%v", err)
		return nil, err
	}

	return &st, err
}

func GetScanTmplByName(e *config.Env, name string) (*model.ScanTemplate, error) {
	st := model.ScanTemplate{}
	query := bson.M{"name": name}
	err, exist := e.MongoCli.FindOne(e.MongoContext(), st.CollectName(), query, &st)
	if err != nil || !exist {
		return nil, err
	}

	return &st, err
}

func AddScanTmpl(e *config.Env, name, typ string, plugins []model.ScanPlugin) error {
	st := model.ScanTemplate{}

	st.Name = name
	st.Type = typ
	st.TmplType = 2 // 2:自定义
	st.Plugins = plugins
	st.CreateTm = utime.CurTime()
	st.UpdateTm = utime.CurTime()

	return e.MongoCli.Insert(e.MongoContext(), st.CollectName(), &st)
}

func UpdateScanTmpl(e *config.Env, id, name string, plugins []model.ScanPlugin) error {
	st := model.ScanTemplate{}
	Id, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return err
	}

	query := bson.M{"_id": Id}
	updateM := bson.M{"$set": bson.M{"name": name, "plugins": plugins}}

	return e.MongoCli.UpdateRaw(e.MongoContext(), st.CollectName(), &query, &updateM, false)
}

func GetScanConfById(e *config.Env, id string) (*model.ScanConf, error) {
	sc := model.ScanConf{}
	Id, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	query := bson.M{"_id": Id}
	err, _ = e.MongoCli.FindOne(e.MongoContext(), sc.CollectName(), query, &sc)
	if err != nil {
		logger.Errorf("get scan conf err:%v", err)
		return nil, err
	}

	return &sc, err
}

func UpdateScanConf(e *config.Env, id string, updater bson.M) error {
	Id, err := bson.ObjectIDFromHex(id)
	if err != nil {
		logger.Errorf("obj _id(%s) err: %v", id, err)
		return err
	}

	var sc model.ScanConf
	return e.MongoCli.Update(e.MongoContext(), sc.CollectName(), bson.M{"_id": Id}, updater, false)
}

// GetDefaultScanTmplMap 获取默认类型的scan tmpl 与id对应map
func GetDefaultScanTmplMap(e *config.Env) (map[string]string, error) {
	var stList []model.ScanTemplate
	tb := (&model.ScanTemplate{}).CollectName()
	err := e.MongoCli.FindAll(e.MongoContext(), tb, bson.M{"tmpl_type": 1}, &stList)
	if err != nil {
		return nil, err
	}
	var tmplIdMap = make(map[string]string)
	for _, st := range stList {
		tmplIdMap[st.Type] = st.ID.Hex()
	}
	return tmplIdMap, nil
}

func defaultScanTmplID(tmplIdMap map[string]string, scanType string) (string, bool) {
	tmplID := strings.TrimSpace(tmplIdMap[scanType])
	return tmplID, tmplID != ""
}

// UpdateScanConfByDomain 当添加域/删除域的时候，更新tb_scan_conf.plans
func UpdateScanConfByDomain(e *config.Env, domain string, isDelete bool) error {
	// 对于delete操作, 遍历扫描配置(baseline/leak/weakpwd)，从plans中移除该domain
	// 对于添加操作，遍历扫描配置(baseline/leak/weakpwd)默认模板，将该domain添加到plans
	var scList []model.ScanConf
	tb := (&model.ScanConf{}).CollectName()
	err := e.MongoCli.FindAll(e.MongoContext(), tb, bson.M{}, &scList)
	if err != nil {
		return err
	}

	tmplIdMap, err := GetDefaultScanTmplMap(e)
	if err != nil {
		return err
	}

	for _, sc := range scList {
		if sc.Plans == nil {
			sc.Plans = make(map[string]string)
		}
		exist := false
		for dm, tmplId := range sc.Plans {
			if isDelete && domain == dm {
				delete(sc.Plans, dm)
				break
			}
			if domain == dm && tmplId != "" {
				exist = true
				break
			}
		}
		if !exist {
			if tmplID, ok := defaultScanTmplID(tmplIdMap, sc.Type); ok {
				sc.Plans[domain] = tmplID
			} else {
				logger.Warnf("skip adding scan conf plan for domain %s: default template not found for type %s", domain, sc.Type)
			}
		}
		update := bson.M{
			"plans":     sc.Plans,
			"update_tm": utime.CurTime(),
		}

		err = e.MongoCli.UpdateById(e.MongoContext(), sc.CollectName(), sc.ID, &update)
		if err != nil {
			logger.Errorf("ignore update scan conf by id(%s) err:%v", sc.ID, err)
			continue
		}
	}

	return nil
}

// UpdateScanConfByDomain 当更新域的时候，更新tb_scan_conf.plans
func UpdateScanConfByDomainV2(e *config.Env, oldDomain, domain string) error {
	var scList []model.ScanConf
	tb := (&model.ScanConf{}).CollectName()
	err := e.MongoCli.FindAll(e.MongoContext(), tb, bson.M{}, &scList)
	if err != nil {
		return err
	}

	tmplIdMap, err := GetDefaultScanTmplMap(e)
	if err != nil {
		return err
	}

	for _, sc := range scList {
		if sc.Plans == nil {
			sc.Plans = make(map[string]string)
		}
		for dm := range sc.Plans {
			// remove old domain
			if dm == oldDomain {
				delete(sc.Plans, dm)
			}
		}
		// add new domain
		if tmplID, ok := defaultScanTmplID(tmplIdMap, sc.Type); ok {
			sc.Plans[domain] = tmplID
		} else {
			logger.Warnf("skip adding scan conf plan for domain %s: default template not found for type %s", domain, sc.Type)
		}
		update := bson.M{
			"plans":     sc.Plans,
			"update_tm": utime.CurTime(),
		}

		err = e.MongoCli.UpdateById(e.MongoContext(), sc.CollectName(), sc.ID, &update)
		if err != nil {
			logger.Errorf("ignore update scan conf by id(%s) err:%v", sc.ID, err)
			continue
		}
	}

	return nil
}

func DeleteScanTmpl(e *config.Env, Id string) error {
	var st model.ScanTemplate

	objId, err := bson.ObjectIDFromHex(Id)
	if err != nil {
		return err
	}

	return e.MongoCli.RemoveById(e.MongoContext(), st.CollectName(), objId)
}

func FindScanPluginSelect(e *config.Env, category string) ([]model.ScanPlugin, error) {
	var sp []model.ScanPlugin
	tb := (&model.ScanPlugin{}).CollectName()

	query := bson.M{"category": category}
	err := e.MongoCli.FindAll(e.MongoContext(), tb, query, &sp)
	if err != nil {
		logger.Errorf("get scan plugin err:%v", err)
		return nil, err
	}

	return sp, err
}

func GetScanPluginById(e *config.Env, Id int32) (model.ScanPlugin, error) {
	sp := model.ScanPlugin{}
	query := bson.M{"_id": Id}
	err, exist := e.MongoCli.FindOne(e.MongoContext(), sp.CollectName(), query, &sp)
	if err != nil || !exist {
		logger.Errorf("get scan plugin err:%v", err)
		return sp, err
	}

	return sp, err
}
