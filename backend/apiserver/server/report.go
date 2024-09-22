package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

func FindExportTask(e *config.Env, typ, status []string, startTm, endTm string, sortTm, limit, skip int32) ([]model.ExportTask, int64, error) {
	var taskList []model.ExportTask
	tb := (&model.ExportTask{}).CollectName()

	query := bson.M{}
	if len(typ) > 0 && typ[0] != "all" {
		query["type"] = bson.M{"$in": typ}
	}
	if len(status) > 0 && status[0] != "all" {
		query["status"] = bson.M{"$in": status}
	}

	if startTm != "" && endTm != "" {
		startTime, err := time.Parse("2006-01-02 15:04:05", startTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, 0, err
		}
		endTime, err := time.Parse("2006-01-02 15:04:05", endTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, 0, err
		}

		//起止日期相同的话截止日期+1，前端没有传时分秒
		if startTm == endTm {
			endTime = endTime.AddDate(0, 0, 1)
		}

		query["create_tm"] = bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour*8 + time.Second)}
	}

	sorter := bson.M{}
	if sortTm != 0 {
		sorter["create_tm"] = sortTm
	}

	count, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	err = e.MongoCli.FindSortByLimitAndSkip(tb, query, sorter, &taskList, int64(limit), int64(skip))
	if err != nil {
		return nil, 0, err
	}

	return taskList, count, nil
}

func GetExportTaskByID(e *config.Env, id string) (*model.ExportTask, error) {
	report := model.ExportTask{}
	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	err, _ = e.MongoCli.FindOne(report.CollectName(), bson.M{"_id": Id}, &report)
	if err != nil {
		return nil, err
	}

	return &report, nil
}

func AddExportTask(e *config.Env, name, typ, taskId string, params map[string]string) error {
	report := &model.ExportTask{
		ID:       primitive.NewObjectID(),
		Name:     name,
		TaskID:   taskId,
		Type:     typ,
		Params:   params,
		Status:   "padding",
		FileType: "xlsx", // 默认导出xlsx
		FilePath: "",
		ErrMsg:   "",
		CreateTm: time.Now(),
		UpdateTm: time.Now(),
	}

	return e.MongoCli.Insert(report.CollectName(), report)
}

func DeleteExportTaskByID(e *config.Env, reportID string) (*model.ExportTask, error) {
	report := &model.ExportTask{}
	objectID, err := primitive.ObjectIDFromHex(reportID)
	if err != nil {
		return nil, err
	}

	err, _ = e.MongoCli.FindOne(report.CollectName(), bson.M{"_id": objectID}, &report)
	if err != nil {
		return nil, err
	}

	err = e.MongoCli.RemoveById(report.CollectName(), objectID)
	if err != nil {
		return report, err
	}
	return report, nil
}
