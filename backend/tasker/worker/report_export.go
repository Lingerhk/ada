package worker

import (
	baseCommon "ada/backend/common"
	"ada/backend/model"
	"ada/infra/base"
	"ada/infra/mongo"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	logger "github.com/sirupsen/logrus"
	"github.com/xuri/excelize/v2"
	"go.mongodb.org/mongo-driver/bson"
	"path"
	"strings"
	"time"
)

type exportReportParams struct {
	Domain  string `json:"domain"` // audit/system no need, multiple split with `,`
	Level   string `json:"level"`  // alert_activity|alert_event|baseline|leak only, multiple split with `,`
	StartTm string `json:"start_tm"`
	EndTm   string `json:"end_tm"`
}

// 需与apiserver/service/scanrisk.go一致
type weakPwdUserList struct {
	Name         string `json:"name"`
	SamName      string `json:"sam_account_name"`
	Password     string `json:"password"`
	LastUpdateTm string `json:"password_last_update_tm"`
	ExpirationTm string `json:"expiration_tm"`
	UpdateTm     string `json:"update_tm"`
	Locked       int32  `json:"is_lock"`
}

func (w *Worker) ExportReportTask(taskId, typ, params string) error {
	logger.Debugf("export report task(task_id:%s, type:%s, params:%s) start!", taskId, typ, params)

	var fileId string
	var err error
	defer func() {
		result := "finish"
		var msg string
		if err != nil {
			msg = err.Error()
			result = "failed"
		}
		_ = updateExportTaskStatus(w.env.MongoCli, taskId, result, msg, fileId)
	}()

	_ = updateExportTaskStatus(w.env.MongoCli, taskId, "doing", "", "")

	var p exportReportParams
	err = json.Unmarshal([]byte(params), &p)
	if err != nil {
		logger.Errorf("unmarshal params err:%v", err)
		return err
	}

	startTime, err := time.Parse("2006-01-02 15:04:05", p.StartTm)
	if err != nil {
		logger.Errorf("parse start_time err:%v", err)
		return err
	}
	endTime, err := time.Parse("2006-01-02 15:04:05", p.EndTm)
	if err != nil {
		logger.Errorf("parse ent_time err:%v", err)
		return err
	}

	domains := strings.Split(p.Domain, ",")
	levels := strings.Split(p.Level, ",")

	switch typ {
	case "alert_event":
		fileId, err = exportAlertEventReport(w.env.MongoCli, startTime, endTime, domains, levels)
	case "alert_activity":
		fileId, err = exportAlertActivityReport(w.env.MongoCli, startTime, endTime, domains, levels)
	case "baseline":
		fileId, err = exportBaselineReport(w.env.MongoCli, startTime, endTime, domains, levels)
	case "leak":
		fileId, err = exportLeakReport(w.env.MongoCli, startTime, endTime, domains, levels)
	case "weakpwd":
		fileId, err = exportWeakPwdReport(w.env.MongoCli, startTime, endTime, domains)
	case "audit":
		fileId, err = exportAuditReport(w.env.MongoCli, startTime, endTime)
	case "system":
		fileId, err = exportSystemReport(w.env.MongoCli, startTime, endTime)
	}
	if err != nil {
		logger.Errorf("export report(type:%s) err:%v", typ, err)
		return err
	}
	if fileId == "" {
		logger.Errorf("export report(type:%s) fileId is empty", typ)
		return fmt.Errorf("export report(type:%s) fileId is empty", typ)
	}

	return nil
}

func exportAlertEventReport(mongoCli mongo.DBAdaptor, startTm, endTm time.Time, domains, levels []string) (string, error) {
	var logList []model.AlertEventESDB
	tb := (&model.AlertEventESDB{}).CollectName()

	query := bson.D{}
	if len(domains) > 0 {
		dcHostnames, err := getAllDcHostnames(mongoCli, domains)
		if err != nil {
			logger.Errorf("get all dc hostnames err:%v", err)
			return "", err
		}
		query = append(query, bson.E{
			Key: "dc_hostname",
			Value: bson.D{
				{Key: "$in", Value: dcHostnames},
			},
		})
	}

	if len(levels) > 0 {
		var levelList []int32
		for _, v := range levels {
			levelList = append(levelList, base.Atoi(v))
		}
		query = append(query, bson.E{
			Key: "level",
			Value: bson.D{
				{Key: "$in", Value: levelList},
			},
		})
	}

	if startTm == endTm {
		endTm = endTm.AddDate(0, 0, 1)
	}
	query = append(query, bson.E{Key: "create_tm", Value: bson.M{"$gte": startTm, "$lte": endTm}})

	sort := bson.M{"create_tm": -1}
	err := mongoCli.FindSortByLimitAndSkip(tb, query, sort, &logList, int64(500000), int64(0))
	if err != nil {
		return "", err
	}

	// //////////////////////////////////
	f := excelize.NewFile()
	defer f.Close()

	sheet1 := "告警事件"
	err = f.SetSheetName("Sheet1", sheet1)
	if err != nil {
		return "", err
	}

	// 写xlsx表头
	head := []string{"威胁名称", "威胁描述", "所在域控", "Att&ck ID", "风险等级", "规则置信度", "标签", "关键字段", "关联行为ID", "开始时间", "结束时间", "持续时间", "检测时间"}
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		return "", err
	}
	err = f.SetSheetRow(sheet1, cell, &head)
	if err != nil {
		return "", err
	}

	sheet1CurCol := 2
	sheet1Columns := []string{"A%d", "B%d", "C%d", "D%d", "E%d", "F%d", "G%d", "H%d", "I%d", "J%d", "K%d", "L%d", "M%d"}

	for index, item := range logList {
		for _, col := range sheet1Columns {
			colName := fmt.Sprintf(col, sheet1CurCol+index)
			switch col {
			case "A%d":
				err = f.SetCellValue(sheet1, colName, item.Title)
			case "B%d":
				err = f.SetCellValue(sheet1, colName, item.Desc)
			case "C%d":
				err = f.SetCellValue(sheet1, colName, item.DcHostname)
			case "D%d":
				err = f.SetCellValue(sheet1, colName, item.AttCkId)
			case "E%d":
				err = f.SetCellValue(sheet1, colName, item.Level)
			case "F%d":
				err = f.SetCellValue(sheet1, colName, item.Status)
			case "G%d":
				err = f.SetCellValue(sheet1, colName, strings.Join(item.Tags, ","))
			case "H%d":
				err = f.SetCellValue(sheet1, colName, item.FieldData)
			case "I%d":
				err = f.SetCellValue(sheet1, colName, strings.Join(item.ActivityIds, ",")) // 关联行为
			case "J%d":
				err = f.SetCellValue(sheet1, colName, time.Unix(item.StartTs/1000, 0).Format("2006-01-02 15:04:05"))
			case "K%d":
				err = f.SetCellValue(sheet1, colName, time.Unix(item.EndTs/1000, 0).Format("2006-01-02 15:04:05"))
			case "L%d":
				err = f.SetCellValue(sheet1, colName, fmt.Sprintf("%ds", (item.EndTs-item.StartTs)/1000))
			case "M%d":
				err = f.SetCellValue(sheet1, colName, item.CreateTm.Add(8*time.Hour))
			}
			if err != nil {
				logger.Warnf("write sheet(colName:%s) err:%v", colName, err)
				return "", err
			}
		}
	}
	fileId := uuid.NewString()
	dstPath := path.Join(baseCommon.DOWNLOAD_PATH, "report", fmt.Sprintf("%s.xlsx", fileId))
	if err = f.SaveAs(dstPath); err != nil {
		logger.Errorf("save file(dstPath:%s) err:%v", dstPath, err)
		return fileId, err
	}
	logger.Debugf("export alert event report ok, path:%s", dstPath)
	return fileId, nil
}

func exportAlertActivityReport(mongoCli mongo.DBAdaptor, startTm, endTm time.Time, domains, levels []string) (string, error) {
	var logList []model.AlertActivityESDB
	tb := (&model.AlertActivityESDB{}).CollectName()

	query := bson.D{}
	if len(domains) > 0 {
		dcHostnames, err := getAllDcHostnames(mongoCli, domains)
		if err != nil {
			logger.Errorf("get all dc hostnames err:%v", err)
			return "", err
		}
		query = append(query, bson.E{
			Key: "dc_hostname",
			Value: bson.D{
				{Key: "$in", Value: dcHostnames},
			},
		})
	}

	if len(levels) > 0 {
		var levelList []int32
		for _, v := range levels {
			levelList = append(levelList, base.Atoi(v))
		}
		query = append(query, bson.E{
			Key: "level",
			Value: bson.D{
				{Key: "$in", Value: levelList},
			},
		})
	}

	if startTm == endTm {
		endTm = endTm.AddDate(0, 0, 1)
	}
	query = append(query, bson.E{
		Key: "create_tm",
		Value: bson.M{
			"$gte": startTm,
			"$lte": endTm,
		},
	})

	logger.Debugf("%#v", query)

	sort := bson.M{"create_tm": -1}
	err := mongoCli.FindSortByLimitAndSkip(tb, query, sort, &logList, int64(500000), int64(0))
	if err != nil {
		logger.Errorf("find alert activity err:%v", err)
		return "", err
	}
	if logList == nil {
		return "", fmt.Errorf("no alert activity found")
	}

	logger.Debugf("3333export alert activity report, domains:%v, levels:%v", domains, levels)

	// //////////////////////////////////
	f := excelize.NewFile()
	defer f.Close()

	sheet1 := "行为侦测事件"
	err = f.SetSheetName("Sheet1", sheet1)
	if err != nil {
		return "", err
	}

	// 写xlsx表头
	head := []string{"威胁名称", "威胁描述", "所在域控", "Att&ck ID", "风险等级", "规则置信度", "标签", "关键字段", "检测时间", "原始日志"}
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		return "", err
	}
	err = f.SetSheetRow(sheet1, cell, &head)
	if err != nil {
		return "", err
	}

	sheet1CurCol := 2
	sheet1Columns := []string{"A%d", "B%d", "C%d", "D%d", "E%d", "F%d", "G%d", "H%d", "I%d", "J%d"}

	logger.Debugf("4444export alert activity report, domains:%v, levels:%v", domains, levels)

	for index, item := range logList {
		for _, col := range sheet1Columns {
			colName := fmt.Sprintf(col, sheet1CurCol+index)
			switch col {
			case "A%d":
				err = f.SetCellValue(sheet1, colName, item.Title)
			case "B%d":
				err = f.SetCellValue(sheet1, colName, item.Desc)
			case "C%d":
				err = f.SetCellValue(sheet1, colName, item.DcHostname)
			case "D%d":
				err = f.SetCellValue(sheet1, colName, item.AttCkId)
			case "E%d":
				err = f.SetCellValue(sheet1, colName, item.Level)
			case "F%d":
				err = f.SetCellValue(sheet1, colName, item.Status)
			case "G%d":
				err = f.SetCellValue(sheet1, colName, strings.Join(item.Tags, ","))
			case "H%d":
				err = f.SetCellValue(sheet1, colName, item.FieldData)
			case "I%d":
				err = f.SetCellValue(sheet1, colName, item.CreateTm.Add(8*time.Hour))
			case "J%d":
				err = f.SetCellValue(sheet1, colName, item.RawLog)
			}
			if err != nil {
				logger.Warnf("write sheet(colName:%s) err:%v", colName, err)
				return "", err
			}
		}
	}
	fileId := uuid.NewString()
	dstPath := path.Join(baseCommon.DOWNLOAD_PATH, "report", fmt.Sprintf("%s.xlsx", fileId))
	if err = f.SaveAs(dstPath); err != nil {
		logger.Errorf("save file(dstPath:%s) err:%v", dstPath, err)
		return fileId, err
	}
	logger.Debugf("export alert activity report ok, path:%s", dstPath)
	return fileId, nil
}

func exportBaselineReport(mongoCli mongo.DBAdaptor, startTm, endTm time.Time, domains, levels []string) (string, error) {
	baseline, err := getLatestScanRiskTaskByType(mongoCli, "baseline")
	if err != nil {
		logger.Errorf("get latest scan risk(type:baseline) task err:%v", err)
		return "", err
	}
	if baseline == nil {
		return "", fmt.Errorf("no baseline result found")
	}

	var logList []model.ScanSubTasks
	tb := (&model.ScanSubTasks{}).CollectName()

	query := bson.D{}
	query = append(query, bson.E{Key: "group_id", Value: baseline.ID.Hex()})
	query = append(query, bson.E{Key: "result.status", Value: 1}) // 只导出有风险的数据
	if len(domains) > 0 {
		query = append(query, bson.E{
			Key: "params.domain",
			Value: bson.D{
				{Key: "$in", Value: domains},
			},
		})
	}

	if len(levels) > 0 {
		var levelList []int32
		for _, v := range levels {
			levelList = append(levelList, base.Atoi(v))
		}
		query = append(query, bson.E{
			Key: "result.plugin.risk_level",
			Value: bson.D{
				{Key: "$in", Value: levelList},
			},
		})
	}

	if startTm == endTm {
		endTm = endTm.AddDate(0, 0, 1)
	}
	query = append(query, bson.E{Key: "update_tm", Value: bson.M{"$gte": startTm, "$lte": endTm}})

	sort := bson.M{"update_tm": -1}
	err = mongoCli.FindSortByLimitAndSkip(tb, query, sort, &logList, int64(10000), int64(0))
	if err != nil {
		return "", err
	}

	// //////////////////////////////////
	f := excelize.NewFile()
	defer f.Close()

	sheet1 := "基线事件"
	err = f.SetSheetName("Sheet1", sheet1)
	if err != nil {
		return "", err
	}

	// 写xlsx表头
	head := []string{"基线名称", "显示名称", "所在域", "基线类型", "风险等级", "风险分值", "检测结果", "检测实例数", "更新时间", "描述", "验证说明", "修复建议"}
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		return "", err
	}
	err = f.SetSheetRow(sheet1, cell, &head)
	if err != nil {
		return "", err
	}

	sheet1CurCol := 2
	sheet1Columns := []string{"A%d", "B%d", "C%d", "D%d", "E%d", "F%d", "G%d", "H%d", "I%d", "J%d", "K%d", "L%d"}
	var instanceList []map[string]interface{}

	for index, item := range logList {
		byteData, _ := json.Marshal(item.Result.Data["instance_list"])
		err = json.Unmarshal(byteData, &instanceList)
		if err != nil {
			logger.Errorf("json unmarshal reuslt.data.instance_list err:%v", err)
			continue
		}

		for _, col := range sheet1Columns {
			colName := fmt.Sprintf(col, sheet1CurCol+index)
			switch col {
			case "A%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Name) // 基线名称
			case "B%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Display) // 显示名称
			case "C%d":
				err = f.SetCellValue(sheet1, colName, item.Params["domain"].(string)) // 域名
			case "D%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Type) // 基线类型
			case "E%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.RiskLevel) // 风险等级
			case "F%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Points) // 风险分值
			case "G%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Status) // 检测结果
			case "H%d":
				err = f.SetCellValue(sheet1, colName, len(instanceList)) // 检测实例数
			case "I%d":
				err = f.SetCellValue(sheet1, colName, item.UpdateTm.Add(8*time.Hour)) // 更新时间
			case "J%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Desc) // 描述
			case "K%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.VerifyDesc) // 验证说明
			case "L%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Suggestion) // 修复建议
			}
			if err != nil {
				logger.Warnf("write sheet(colName:%s) err:%v", colName, err)
				return "", err
			}
		}
	}
	fileId := uuid.NewString()
	dstPath := path.Join(baseCommon.DOWNLOAD_PATH, "report", fmt.Sprintf("%s.xlsx", fileId))
	if err = f.SaveAs(dstPath); err != nil {
		logger.Errorf("save file(dstPath:%s) err:%v", dstPath, err)
		return fileId, err
	}
	logger.Debugf("export baseline report ok, path:%s", dstPath)
	return fileId, nil
}

func exportLeakReport(mongoCli mongo.DBAdaptor, startTm, endTm time.Time, domains, levels []string) (string, error) {
	leak, err := getLatestScanRiskTaskByType(mongoCli, "leak")
	if err != nil {
		logger.Errorf("get latest scan risk(type:leak) task err:%v", err)
		return "", err
	}
	if leak == nil {
		return "", fmt.Errorf("no leak result found")
	}

	var logList []model.ScanSubTasks
	tb := (&model.ScanSubTasks{}).CollectName()

	query := bson.D{}
	query = append(query, bson.E{Key: "group_id", Value: leak.ID.Hex()})
	query = append(query, bson.E{Key: "result.status", Value: 1}) // 只导出有风险的数据
	if len(domains) > 0 {
		query = append(query, bson.E{
			Key: "params.domain",
			Value: bson.D{
				{Key: "$in", Value: domains},
			},
		})
	}

	if len(levels) > 0 {
		var levelList []int32
		for _, v := range levels {
			levelList = append(levelList, base.Atoi(v))
		}
		query = append(query, bson.E{
			Key: "result.plugin.risk_level",
			Value: bson.D{
				{Key: "$in", Value: levelList},
			},
		})
	}

	if startTm == endTm {
		endTm = endTm.AddDate(0, 0, 1)
	}
	query = append(query, bson.E{Key: "update_tm", Value: bson.M{"$gte": startTm, "$lte": endTm}})

	sort := bson.M{"update_tm": -1}
	err = mongoCli.FindSortByLimitAndSkip(tb, query, sort, &logList, int64(10000), int64(0))
	if err != nil {
		return "", err
	}

	// //////////////////////////////////
	f := excelize.NewFile()
	defer f.Close()

	sheet1 := "漏洞事件"
	err = f.SetSheetName("Sheet1", sheet1)
	if err != nil {
		return "", err
	}

	// 写xlsx表头
	head := []string{"漏洞名称", "显示名称", "所在域", "域控制器", "漏洞类型", "风险等级", "风险分值", "检测结果", "更新时间", "描述", "修复建议"}
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		return "", err
	}
	err = f.SetSheetRow(sheet1, cell, &head)
	if err != nil {
		return "", err
	}
	sheet1CurCol := 2
	sheet1Columns := []string{"A%d", "B%d", "C%d", "D%d", "E%d", "F%d", "G%d", "H%d", "I%d", "J%d", "K%d"}

	for index, item := range logList {
		for _, col := range sheet1Columns {
			colName := fmt.Sprintf(col, sheet1CurCol+index)
			switch col {
			case "A%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Name) // 漏洞名称
			case "B%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Display) // 显示名称
			case "C%d":
				err = f.SetCellValue(sheet1, colName, item.Params["domain"].(string)) // 域名
			case "D%d":
				err = f.SetCellValue(sheet1, colName, fmt.Sprintf("%s.%s", item.Params["hostname"].(string), item.Params["domain"].(string))) // 域控制器
			case "E%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Type) // 漏洞类型
			case "F%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.RiskLevel) // 风险等级
			case "G%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Points) // 风险分值
			case "H%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Status) // 检测结果
			case "I%d":
				err = f.SetCellValue(sheet1, colName, item.UpdateTm.Add(8*time.Hour)) // 更新时间
			case "J%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Desc) // 描述
			case "K%d":
				err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Suggestion) // 修复建议
			}
			if err != nil {
				logger.Warnf("write sheet(colName:%s) err:%v", colName, err)
				return "", err
			}
		}
	}
	fileId := uuid.NewString()
	dstPath := path.Join(baseCommon.DOWNLOAD_PATH, "report", fmt.Sprintf("%s.xlsx", fileId))
	if err = f.SaveAs(dstPath); err != nil {
		logger.Errorf("save file(dstPath:%s) err:%v", dstPath, err)
		return fileId, err
	}
	logger.Debugf("export leak report ok, path:%s", dstPath)
	return fileId, nil
}

func exportWeakPwdReport(mongoCli mongo.DBAdaptor, startTm, endTm time.Time, domains []string) (string, error) {
	weakPwd, err := getLatestScanRiskTaskByType(mongoCli, "weakpwd")
	if err != nil {
		logger.Errorf("get latest scan risk(type:weakpwd) task err:%v", err)
		return "", err
	}
	if weakPwd == nil {
		return "", fmt.Errorf("no weakpwd result found")
	}

	var logList []model.ScanSubTasks
	tb := (&model.ScanSubTasks{}).CollectName()

	query := bson.D{}
	query = append(query, bson.E{Key: "group_id", Value: weakPwd.ID.Hex()})
	if len(domains) > 0 {
		query = append(query, bson.E{
			Key: "params.domain",
			Value: bson.D{
				{Key: "$in", Value: domains},
			},
		})
	}

	if startTm == endTm {
		endTm = endTm.AddDate(0, 0, 1)
	}
	query = append(query, bson.E{Key: "update_tm", Value: bson.M{"$gte": startTm, "$lte": endTm}})

	sort := bson.M{"update_tm": -1}
	err = mongoCli.FindSortByLimitAndSkip(tb, query, sort, &logList, int64(10000), int64(0))
	if err != nil {
		return "", err
	}

	var userList []weakPwdUserList

	// //////////////////////////////////
	f := excelize.NewFile()
	defer f.Close()

	sheet1 := "弱口令事件"
	err = f.SetSheetName("Sheet1", sheet1)
	if err != nil {
		return "", err
	}

	// 写xlsx表头
	head := []string{"用户名", "SamAccountName", "密码", "密码过期时间", "密码修改时间", "所在域", "用户锁定状态", "更新时间", "描述", "修复建议"}
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		return "", err
	}
	err = f.SetSheetRow(sheet1, cell, &head)
	if err != nil {
		return "", err
	}
	sheet1CurCol := 2
	sheet1Columns := []string{"A%d", "B%d", "C%d", "D%d", "E%d", "F%d", "G%d", "H%d", "I%d", "J%d"}

	var idx int
	for _, item := range logList {
		domain := item.Result.Data["domain"].(string)
		byteData, err := json.Marshal(item.Result.Data["users"])
		if err != nil {
			logger.Errorf("json marshal reuslt.data.users err:%v", err)
			return "", err
		}
		err = json.Unmarshal(byteData, &userList)
		if err != nil {
			logger.Errorf("json unmarshal reuslt.data.users err:%v", err)
			return "", err
		}
		if len(userList) == 0 {
			continue
		}

		if len(domains) > 0 {
			if !base.InArray(domain, domains) {
				continue
			}
		}

		for _, user := range userList {
			for _, col := range sheet1Columns {
				colName := fmt.Sprintf(col, sheet1CurCol+idx)
				switch col {
				case "A%d":
					err = f.SetCellValue(sheet1, colName, user.Name)
				case "B%d":
					err = f.SetCellValue(sheet1, colName, user.SamName)
				case "C%d":
					err = f.SetCellValue(sheet1, colName, user.Password)
				case "D%d":
					err = f.SetCellValue(sheet1, colName, user.ExpirationTm)
				case "E%d":
					err = f.SetCellValue(sheet1, colName, user.LastUpdateTm)
				case "F%d":
					err = f.SetCellValue(sheet1, colName, item.Params["domain"].(string))
				case "G%d":
					err = f.SetCellValue(sheet1, colName, user.Locked)
				case "H%d":
					err = f.SetCellValue(sheet1, colName, user.UpdateTm)
				case "I%d":
					err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Desc) // 描述
				case "J%d":
					err = f.SetCellValue(sheet1, colName, item.Result.Plugin.Suggestion) // 修复建议
				}
				if err != nil {
					logger.Warnf("write sheet(colName:%s) err:%v", colName, err)
					return "", err
				}
			}

			idx += 1
		}
	}
	fileId := uuid.NewString()
	dstPath := path.Join(baseCommon.DOWNLOAD_PATH, "report", fmt.Sprintf("%s.xlsx", fileId))
	if err = f.SaveAs(dstPath); err != nil {
		logger.Errorf("save file(dstPath:%s) err:%v", dstPath, err)
		return fileId, err
	}
	logger.Debugf("export weakpwd report ok, path:%s", dstPath)
	return fileId, nil
}

func exportAuditReport(mongoCli mongo.DBAdaptor, startTm, endTm time.Time) (string, error) {
	var logList []model.AuditLog
	tb := (&model.AuditLog{}).CollectName()

	sort := bson.M{"create_tm": -1}
	query := bson.M{"create_tm": bson.M{"$gte": startTm, "$lte": endTm}}
	query["status"] = 0
	err := mongoCli.FindWithMultiple(tb, query, nil, sort, &logList, 1000000, 0)
	if err != nil {
		return "", err
	}

	f := excelize.NewFile()
	defer f.Close()

	sheet1 := "日志审计"
	err = f.SetSheetName("Sheet1", sheet1)
	if err != nil {
		return "", err
	}

	// 写xlsx表头
	head := []string{"登录用户", "登录IP", "审计事件", "事件属性", "事件结果", "审计时间"}
	cell, err := excelize.CoordinatesToCellName(1, 1)
	if err != nil {
		return "", err
	}
	err = f.SetSheetRow(sheet1, cell, &head)
	if err != nil {
		return "", err
	}

	sheet1CurCol := 2
	sheet1Columns := []string{"A%d", "B%d", "C%d", "D%d", "E%d", "F%d"}
	for index, item := range logList {
		for _, col := range sheet1Columns {
			colName := fmt.Sprintf(col, sheet1CurCol+index)
			switch col {
			case "A%d":
				err = f.SetCellValue(sheet1, colName, item.Username)
			case "B%d":
				err = f.SetCellValue(sheet1, colName, item.ClientIp)
			case "C%d":
				err = f.SetCellValue(sheet1, colName, item.Event)
			case "D%d":
				err = f.SetCellValue(sheet1, colName, item.EventArgs)
			case "E%d":
				err = f.SetCellValue(sheet1, colName, item.EventResult)
			case "F%d":
				err = f.SetCellValue(sheet1, colName, item.CreateTm.Add(8*time.Hour))
			}
			if err != nil {
				logger.Warnf("write sheet(colName:%s) err:%v", colName, err)
				return "", err
			}
		}
	}

	fileId := uuid.NewString()
	dstPath := path.Join(baseCommon.DOWNLOAD_PATH, "report", fmt.Sprintf("%s.xlsx", fileId))
	if err = f.SaveAs(dstPath); err != nil {
		logger.Errorf("save file(dstPath:%s) err:%v", dstPath, err)
		return fileId, err
	}
	logger.Debugf("export audit report ok, path:%s", dstPath)
	return fileId, nil
}

func exportSystemReport(mongoCli mongo.DBAdaptor, startTm, endTm time.Time) (string, error) {
	return "", nil
}

func updateExportTaskStatus(mongoCli mongo.DBAdaptor, taskId, status, errMsg, filePath string) error {
	et := model.ExportTask{}

	query := bson.M{"task_id": taskId}
	updateM := bson.M{"$set": bson.M{"status": status, "file_path": filePath}}
	if errMsg != "" {
		updateM["$set"] = bson.M{"status": status, "err_msg": errMsg}
	}

	return mongoCli.UpdateRaw(et.CollectName(), &query, &updateM, false)
}

func getLatestScanRiskTaskByType(mongoCli mongo.DBAdaptor, typ string) (*model.ScanTasks, error) {
	var st []model.ScanTasks
	tb := (&model.ScanTasks{}).CollectName()

	query := bson.M{"type": typ, "status": "FINISH"}
	sort := bson.M{"create_tm": -1}
	err := mongoCli.FindSortByLimitAndSkip(tb, query, sort, &st, 1, 0)
	if err != nil {
		return nil, err
	}
	if len(st) == 0 {
		return nil, nil
	}

	return &st[0], err
}

func getAllDcHostnames(mongoCli mongo.DBAdaptor, domains []string) ([]string, error) {
	var dcHostnames []string

	var dm model.Domain
	for _, domain := range domains {
		err, exist := mongoCli.FindOne(dm.CollectName(), bson.M{"name": domain}, &dm)
		if err != nil || !exist {
			return nil, err
		}
		for _, dc := range dm.DCList {
			dcHostnames = append(dcHostnames, fmt.Sprintf("%s.%s", dc.HostName, domain))
		}
	}

	return dcHostnames, nil
}
