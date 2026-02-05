package scgo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/bson"
	logger "github.com/sirupsen/logrus"
)

func nowUTC() time.Time { return time.Now().UTC() }

func (s *Service) updateScanTaskByIDHex(idHex string, update bson.M) error {
	id, err := bson.ObjectIDFromHex(idHex)
	if err != nil {
		return err
	}
	return s.MongoCli.UpdateRaw("tb_scan_tasks", bson.M{"_id": id}, update, false)
}

func (s *Service) updateSubTaskByTaskID(taskID string, update bson.M) error {
	return s.MongoCli.UpdateRaw("tb_scan_subtasks", bson.M{"task_id": taskID}, update, false)
}

func (s *Service) countSubTasks(groupID, status string) (int64, error) {
	q := bson.M{"group_id": groupID}
	if status != "" {
		q["status"] = status
	}
	return s.MongoCli.FindCount("tb_scan_subtasks", q)
}

func (s *Service) getScanTaskByIDHex(idHex string) (bson.M, error) {
	id, err := bson.ObjectIDFromHex(idHex)
	if err != nil {
		return nil, err
	}
	var doc bson.M
	err, exist := s.MongoCli.FindOne("tb_scan_tasks", bson.M{"_id": id}, &doc)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, fmt.Errorf("scan task not found: %s", idHex)
	}
	return doc, nil
}

func (s *Service) getSubTaskByTaskID(taskID string) (bson.M, error) {
	var doc bson.M
	err, exist := s.MongoCli.FindOne("tb_scan_subtasks", bson.M{"task_id": taskID}, &doc)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, fmt.Errorf("subtask not found: %s", taskID)
	}
	return doc, nil
}

func pushNotify(rdb *redis.Client, payload map[string]any) {
	b, _ := json.Marshal(payload)
	_ = rdb.LPush(context.Background(), "ada:server:notify_queue", string(b)).Err()
}

func logPluginError(module string, out string, errStr string, err error) {
	logger.Errorf("plugin module=%s err=%v", module, err)
	if out != "" {
		logger.Debugf("plugin stdout: %s", out)
	}
	if errStr != "" {
		logger.Debugf("plugin stderr: %s", errStr)
	}
}
