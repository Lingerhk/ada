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
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (w *Worker) ScannerBaselineTask(domainTmplMap string) error {
	var dtm map[string]string
	_ = json.Unmarshal([]byte(domainTmplMap), &dtm)

	logger.Debugf("start ScannerBaselineTask, plans:%#v", dtm)

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
		st.ID = primitive.NewObjectID()
		st.Type = "baseline"
		st.Trigger = "once"
		st.Status = common.ScanTaskStatusRun
		st.Domain = dm.Name
		st.TemplateId = sTmpl.ID.Hex()
		st.SubTasksTotal = int32(subTasksTotal)
		st.SubTasksFin = 0
		st.CreateTm = utime.CurTime()
		st.UpdateTm = utime.CurTime()
		err = w.env.MongoCli.Insert(st.CollectName(), &st)
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

			subTask.ID = primitive.NewObjectID()
			subTask.TaskID = primitive.NewObjectID().Hex()
			subTask.GroupID = st.ID.Hex()
			subTask.Status = common.ScanTaskStatusPend
			subTask.Params = kwargs
			subTask.CreateTm = utime.CurTime()
			subTask.UpdateTm = utime.CurTime()
			err = w.env.MongoCli.Insert(subTask.CollectName(), &subTask)
			if err != nil {
				logger.Errorf("insert scan_sub_task err:%v", err)
				continue
			}

			w.sendTaskToScanner(st.Type, subTask.TaskID, kwargs)
		}
	}

	return nil
}

func (w *Worker) ScannerLeakTask(domainTmplMap string) error {
	var dtm map[string]string
	_ = json.Unmarshal([]byte(domainTmplMap), &dtm)

	logger.Debugf("start ScannerLeakTask, plans:%#v", dtm)

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
		st.ID = primitive.NewObjectID()
		st.Type = "leak"
		st.Trigger = "once"
		st.Status = common.ScanTaskStatusRun
		st.Domain = dm.Name
		st.TemplateId = sTmpl.ID.Hex()
		st.SubTasksTotal = int32(subTasksTotal)
		st.SubTasksFin = 0
		st.CreateTm = utime.CurTime()
		st.UpdateTm = utime.CurTime()
		err = w.env.MongoCli.Insert(st.CollectName(), &st)
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

				subTask.ID = primitive.NewObjectID()
				subTask.TaskID = primitive.NewObjectID().Hex()
				subTask.GroupID = st.ID.Hex()
				subTask.Status = common.ScanTaskStatusPend
				subTask.Params = kwargs
				subTask.CreateTm = utime.CurTime()
				subTask.UpdateTm = utime.CurTime()
				err = w.env.MongoCli.Insert(subTask.CollectName(), &subTask)
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

func (w *Worker) ScannerWeakPwdTask(domainTmplMap string) error {
	var dtm map[string]string
	_ = json.Unmarshal([]byte(domainTmplMap), &dtm)

	logger.Debugf("start ScannerWeakPwdTask, plans:%#v", dtm)

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

		// 判断扫描类型: 当存在tb_domain_xxx_hash表时，表明该域user hash已经缓存在本地，可执行增量扫描，否则全量扫描
		tb := fmt.Sprintf("tb_domain_%s_hash", domainName)
		total, err := w.env.MongoCli.FindCount(tb, bson.M{})
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
		st.ID = primitive.NewObjectID()
		st.Type = "weakpwd"
		st.Trigger = "once"
		st.Status = common.ScanTaskStatusRun
		st.Domain = dm.Name
		st.TemplateId = sTmpl.ID.Hex()
		st.SubTasksTotal = int32(subTasksTotal)
		st.SubTasksFin = 0
		st.CreateTm = utime.CurTime()
		st.UpdateTm = utime.CurTime()
		err = w.env.MongoCli.Insert(st.CollectName(), &st)
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

				subTask.ID = primitive.NewObjectID()
				subTask.TaskID = primitive.NewObjectID().Hex()
				subTask.GroupID = st.ID.Hex()
				subTask.Status = common.ScanTaskStatusPend
				subTask.Params = kwargs
				subTask.CreateTm = utime.CurTime()
				subTask.UpdateTm = utime.CurTime()
				err = w.env.MongoCli.Insert(subTask.CollectName(), &subTask)
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

func (w *Worker) ScannerRecheckTask(scanType, subTaskId string) error {
	logger.Debugf("start ScannerRecheckTask, scan_type:%s, subtask_id:%s", scanType, subTaskId)

	var err error
	var subTask model.ScanSubTasks

	subTask.ID, err = primitive.ObjectIDFromHex(subTaskId)
	if err != nil {
		logger.Errorf("invalid subtask_id(%s), err:%v", subTaskId, err)
		return err
	}

	err, exist := w.env.MongoCli.FindOne(subTask.CollectName(), bson.M{"_id": subTask.ID}, &subTask)
	if err != nil || !exist {
		return err
	}

	subTask.Status = common.ScanTaskStatusPend
	err = w.env.MongoCli.UpdateById(subTask.CollectName(), subTask.ID, &subTask)
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
	err, exist := w.env.MongoCli.FindOne(dm.CollectName(), bson.M{"name": domain}, &dm)
	if err != nil || !exist {
		return nil, err
	}

	return &dm, nil
}

func (w *Worker) getTemplateById(templateId string) (*model.ScanTemplate, error) {
	var st model.ScanTemplate

	Id, err := primitive.ObjectIDFromHex(templateId)
	if err != nil {
		return nil, err
	}

	err, exist := w.env.MongoCli.FindOne(st.CollectName(), bson.M{"_id": Id}, &st)
	if err != nil || !exist {
		return nil, err
	}

	return &st, nil
}

func (w *Worker) getAssetUserNameList(domain string) ([]string, error) {
	ignoreUser := []string{"Guest", "DefaultAccount", "krbtgt"}

	var userList []model.AssetUser
	tb := (&model.AssetUser{}).CollectName()
	if err := w.env.MongoCli.FindSelect(tb, bson.M{"domain": domain, "isDelete": false}, bson.M{"sAMAccountName": 1}, &userList); err != nil {
		return nil, err
	}

	var userNames []string
	for _, u := range userList {
		ignored := false
		for _, iu := range ignoreUser {
			if u.SAMAccountName == iu {
				ignored = true
				break
			}
		}
		if ignored {
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
