package worker

import (
	"ada/backend/common"
	"ada/backend/model"
	"ada/infra/gocelery"
	utime "ada/infra/time"
	"context"
	"encoding/json"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"slices"
	"strings"
)

const (
	scanTriggerOnce  = "once"
	scanTriggerCycle = "cycle"

	domainUserHashCollection = "tb_domain_user_hash"
)

type scannerTaskPayload struct {
	Plans   map[string]string `json:"plans"`
	Trigger string            `json:"trigger"`
}

func parseScannerTaskPayload(raw string) (map[string]string, string) {
	var legacyPlans map[string]string
	if err := json.Unmarshal([]byte(raw), &legacyPlans); err == nil && legacyPlans != nil {
		return legacyPlans, scanTriggerOnce
	}

	var payload scannerTaskPayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		logger.Errorf("parse scanner task payload error: %v", err)
		return map[string]string{}, scanTriggerOnce
	}

	trigger := strings.ToLower(strings.TrimSpace(payload.Trigger))
	if trigger != scanTriggerCycle {
		trigger = scanTriggerOnce
	}
	if payload.Plans == nil {
		payload.Plans = map[string]string{}
	}
	return payload.Plans, trigger
}

func (w *Worker) ScannerBaselineTask(ctx context.Context, domainTmplMap string) error {
	w = w.withContext(ctx)
	dtm, trigger := parseScannerTaskPayload(domainTmplMap)

	logger.Debugf("start ScannerBaselineTask, trigger:%s, plans:%#v", trigger, dtm)

	for domainName, templateId := range dtm {
		dm, err := w.getDomainByName(domainName)
		if err != nil {
			logger.Warnf("domaon %s not found, will ignore!", domainName)
			return err
		}

		sTmpl, err := w.getTemplateById(templateId)
		if err != nil {
			logger.Errorf("get scan tmpl by id(%s) err:%v", templateId, err)
			return err
		}

		subTasksTotal := len(sTmpl.Plugins) * len(dtm)

		var st model.ScanTasks
		st.ID = bson.NewObjectID()
		st.Type = "baseline"
		st.Trigger = trigger
		st.Status = common.ScanTaskStatusRun
		st.Domain = dm.Name
		st.TemplateId = sTmpl.ID.Hex()
		st.SubTasksTotal = int32(subTasksTotal)
		st.SubTasksFin = 0
		st.CreateTm = utime.CurTime()
		st.UpdateTm = utime.CurTime()
		err = w.env.MongoCli.Insert(w.env.MongoContext(), st.CollectName(), &st)
		if err != nil {
			logger.Errorf("insert scan_task err:%v", err)
			return err
		}

		var subTask model.ScanSubTasks
		kwargs := make(map[string]any)

		for _, plug := range sTmpl.Plugins {
			kwargs["plugin_id"] = plug.ID
			kwargs["group_id"] = st.ID.Hex()
			kwargs["domain"] = dm.Name
			kwargs["template_id"] = sTmpl.ID.Hex()

			subTask.ID = bson.NewObjectID()
			subTask.TaskID = bson.NewObjectID().Hex()
			subTask.GroupID = st.ID.Hex()
			subTask.Status = common.ScanTaskStatusPend
			subTask.Params = kwargs
			subTask.CreateTm = utime.CurTime()
			subTask.UpdateTm = utime.CurTime()
			err = w.env.MongoCli.Insert(w.env.MongoContext(), subTask.CollectName(), &subTask)
			if err != nil {
				logger.Errorf("insert scan_sub_task err:%v", err)
				continue
			}

			w.sendTaskToScanner(st.Type, subTask.TaskID, kwargs)
		}
	}

	return nil
}

func (w *Worker) ScannerLeakTask(ctx context.Context, domainTmplMap string) error {
	w = w.withContext(ctx)
	dtm, trigger := parseScannerTaskPayload(domainTmplMap)

	logger.Debugf("start ScannerLeakTask, trigger:%s, plans:%#v", trigger, dtm)

	for domainName, templateId := range dtm {
		dm, err := w.getDomainByName(domainName)
		if err != nil {
			logger.Warnf("domain %s not found, will ignore!", domainName)
			return err
		}

		sTmpl, err := w.getTemplateById(templateId)
		if err != nil {
			logger.Errorf("get scan tmpl by id(%s) err:%v", templateId, err)
			return err
		}

		subTasksTotal := len(sTmpl.Plugins) * len(dtm) * len(dm.DCList)

		var st model.ScanTasks
		st.ID = bson.NewObjectID()
		st.Type = "leak"
		st.Trigger = trigger
		st.Status = common.ScanTaskStatusRun
		st.Domain = dm.Name
		st.TemplateId = sTmpl.ID.Hex()
		st.SubTasksTotal = int32(subTasksTotal)
		st.SubTasksFin = 0
		st.CreateTm = utime.CurTime()
		st.UpdateTm = utime.CurTime()
		err = w.env.MongoCli.Insert(w.env.MongoContext(), st.CollectName(), &st)
		if err != nil {
			logger.Errorf("insert scan_task err:%v", err)
			return err
		}

		var subTask model.ScanSubTasks
		kwargs := make(map[string]any)

		for _, dc := range dm.DCList {
			for _, plug := range sTmpl.Plugins {
				kwargs["plugin_id"] = plug.ID
				kwargs["group_id"] = st.ID.Hex()
				kwargs["domain"] = dm.Name
				kwargs["template_id"] = sTmpl.ID.Hex()
				kwargs["hostname"] = dc.HostName

				subTask.ID = bson.NewObjectID()
				subTask.TaskID = bson.NewObjectID().Hex()
				subTask.GroupID = st.ID.Hex()
				subTask.Status = common.ScanTaskStatusPend
				subTask.Params = kwargs
				subTask.CreateTm = utime.CurTime()
				subTask.UpdateTm = utime.CurTime()
				err = w.env.MongoCli.Insert(w.env.MongoContext(), subTask.CollectName(), &subTask)
				if err != nil {
					logger.Errorf("insert scan_sub_task err:%v", err)
					continue
				}

				w.sendTaskToScanner(st.Type, subTask.TaskID, kwargs)
			}
		}
	}

	return nil
}

func (w *Worker) ScannerWeakPwdTask(ctx context.Context, domainTmplMap string) error {
	w = w.withContext(ctx)
	dtm, trigger := parseScannerTaskPayload(domainTmplMap)

	logger.Debugf("start ScannerWeakPwdTask, trigger:%s, plans:%#v", trigger, dtm)

	for domainName, templateId := range dtm {
		dm, err := w.getDomainByName(domainName)
		if err != nil {
			logger.Warnf("domaon %s not found, will ignore!", domainName)
			continue
		}

		sTmpl, err := w.getTemplateById(templateId)
		if err != nil {
			logger.Errorf("get scan tmpl by id(%s) err:%v", templateId, err)
			continue
		}

		userList, err := w.getAssetUserNameList(domainName)
		if err != nil {
			logger.Errorf("get asset user name list err:%v", err)
			continue
		}

		// 判断扫描类型: 当 tb_domain_user_hash 存在当前域记录时，表明该域 user hash 已缓存，可执行增量扫描，否则全量扫描
		total, err := w.env.MongoCli.FindCount(w.env.MongoContext(), domainUserHashCollection, bson.M{"domain": dm.Name})
		if err != nil {
			logger.Errorf("count ad user hash table err:%v", err)
			continue
		}
		scanType := "full_update"
		if total > 0 {
			scanType = "incremental_update"
		}

		subTasksTotal := len(sTmpl.Plugins) * len(userList)

		var st model.ScanTasks
		st.ID = bson.NewObjectID()
		st.Type = "weakpwd"
		st.Trigger = trigger
		st.Status = common.ScanTaskStatusRun
		st.Domain = dm.Name
		st.TemplateId = sTmpl.ID.Hex()
		st.SubTasksTotal = int32(subTasksTotal)
		st.SubTasksFin = 0
		st.CreateTm = utime.CurTime()
		st.UpdateTm = utime.CurTime()
		err = w.env.MongoCli.Insert(w.env.MongoContext(), st.CollectName(), &st)
		if err != nil {
			logger.Errorf("insert scan_task err:%v", err)
			continue
		}

		var subTask model.ScanSubTasks
		kwargs := make(map[string]any)

		// 将userList分组下发任务，每组300个
		chunkSize := 300
		for _, plug := range sTmpl.Plugins {
			kwargs["plugin_id"] = plug.ID
			kwargs["group_id"] = st.ID.Hex()
			kwargs["domain"] = dm.Name
			kwargs["template_id"] = sTmpl.ID.Hex()
			kwargs["scan_type"] = scanType

			//分组下发任务
			for i := 0; i < len(userList); i += chunkSize {
				end := i + chunkSize
				if end > len(userList) {
					end = len(userList)
				}
				chunk := userList[i:end]
				kwargs["user_list"] = chunk

				subTask.ID = bson.NewObjectID()
				subTask.TaskID = bson.NewObjectID().Hex()
				subTask.GroupID = st.ID.Hex()
				subTask.Status = common.ScanTaskStatusPend
				subTask.Params = kwargs
				subTask.CreateTm = utime.CurTime()
				subTask.UpdateTm = utime.CurTime()
				err = w.env.MongoCli.Insert(w.env.MongoContext(), subTask.CollectName(), &subTask)
				if err != nil {
					logger.Errorf("insert scan_sub_task err:%v", err)
					continue
				}

				kwargs["user_list"] = nil
				w.sendTaskToScanner(st.Type, subTask.TaskID, kwargs)
			}
		}
	}

	return nil
}

func (w *Worker) ScannerRecheckTask(ctx context.Context, scanType, subTaskId string) error {
	w = w.withContext(ctx)
	logger.Debugf("start ScannerRecheckTask, scan_type:%s, subtask_id:%s", scanType, subTaskId)

	var err error
	var subTask model.ScanSubTasks

	subTask.ID, err = bson.ObjectIDFromHex(subTaskId)
	if err != nil {
		logger.Errorf("invalid subtask_id(%s), err:%v", subTaskId, err)
		return err
	}

	err, exist := w.env.MongoCli.FindOne(w.env.MongoContext(), subTask.CollectName(), bson.M{"_id": subTask.ID}, &subTask)
	if err != nil || !exist {
		return err
	}

	subTask.Status = common.ScanTaskStatusPend
	err = w.env.MongoCli.UpdateById(w.env.MongoContext(), subTask.CollectName(), subTask.ID, &subTask)
	if err != nil {
		logger.Errorf("insert scan_sub_task err:%v", err)
		return err
	}

	subTask.Params["retry_id"] = subTask.TaskID

	w.sendTaskToScanner(scanType, subTask.TaskID, subTask.Params)

	return nil
}

func (w *Worker) getDomainByName(domain string) (*model.Domain, error) {
	var dm model.Domain
	err, exist := w.env.MongoCli.FindOne(w.env.MongoContext(), dm.CollectName(), bson.M{"name": domain}, &dm)
	if err != nil || !exist {
		return nil, err
	}

	return &dm, nil
}

func (w *Worker) getTemplateById(templateId string) (*model.ScanTemplate, error) {
	var st model.ScanTemplate

	Id, err := bson.ObjectIDFromHex(templateId)
	if err != nil {
		return nil, err
	}

	err, exist := w.env.MongoCli.FindOne(w.env.MongoContext(), st.CollectName(), bson.M{"_id": Id}, &st)
	if err != nil || !exist {
		return nil, err
	}

	return &st, nil
}

func (w *Worker) getAssetUserNameList(domain string) ([]string, error) {
	ignoreUser := []string{"Guest", "DefaultAccount", "krbtgt"}

	var userList []model.AssetUser
	tb := (&model.AssetUser{}).CollectName()
	if err := w.env.MongoCli.FindSelect(w.env.MongoContext(), tb, bson.M{"domain": domain, "isDelete": false}, bson.M{"sAMAccountName": 1}, &userList); err != nil {
		return nil, err
	}

	var userNames []string
	for _, u := range userList {
		if slices.Contains(ignoreUser, u.SAMAccountName) {
			continue
		}

		userNames = append(userNames, u.SAMAccountName)
	}

	return userNames, nil
}

func (w *Worker) sendTaskToScanner(taskType, taskId string, kwargs map[string]any) {
	ctx := context.Background()
	taskCli, _ := gocelery.NewCeleryClient(
		gocelery.NewRedisBroker(ctx, w.env.RedisCli),
		gocelery.NewRedisBackend(ctx, w.env.RedisCli),
		5,
	)

	taskName := fmt.Sprintf("tasks.%s.execute_%s", taskType, taskType)
	taskRet, err := taskCli.DelayKwargs(taskName, taskId, kwargs)
	if err != nil {
		logger.Errorf("send task %s to scanner err:%v", taskName, err)
		return
	}

	logger.Debugf("send task %s to scanner, task_uuid:%s", taskName, taskRet.TaskID)
}
