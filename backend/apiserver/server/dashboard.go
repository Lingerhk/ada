package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
)

// GetAlertCountsByLevel returns alert counts grouped by level
func GetAlertCountsByLevel(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)
	tb := (&model.AlertEventESDB{}).CollectName()

	// Query for unprocessed alerts (event_status = 0)
	query := bson.D{
		{Key: "event_status", Value: 0},
	}

	// Filter by domains if specified
	if len(domains) > 0 {
		query = append(query, bson.E{Key: "dc_hostname", Value: bson.D{{Key: "$in", Value: domains}}})
	}

	// Get all alert events
	var alerts []model.AlertEventESDB
	err := e.MongoCli.FindAll(tb, query, &alerts)
	if err != nil {
		logger.Errorf("find alert events err:%v", err)
		return result, err
	}

	// Count by level
	levelCounts := make(map[int32]int32)
	for _, alert := range alerts {
		levelCounts[alert.Level]++
	}

	// Convert to string keys: "high"=2, "medium"=3, "low"=4/5
	for level, count := range levelCounts {
		switch level {
		case 2:
			result["high"] = count
		case 3:
			result["medium"] = count
		case 4, 5:
			result["low"] += count
		}
	}

	return result, nil
}

// GetBaselineCountsByLevel returns baseline issue counts by level from latest scan task
func GetBaselineCountsByLevel(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)

	// Get latest baseline scan task for each domain
	for _, domain := range domains {
		// Query latest baseline scan task
		taskQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "type", Value: "baseline"},
			{Key: "status", Value: "FINISH"},
		}

		var tasks []model.ScanTasks
		sort := bson.M{"create_tm": -1}
		err := e.MongoCli.FindSortByLimitAndSkip((&model.ScanTasks{}).CollectName(), taskQuery, sort, &tasks, 1, 0)
		if err != nil || len(tasks) == 0 {
			logger.Errorf("find baseline tasks err:%v", err)
			continue
		}

		// Get subtasks for this scan task and count by risk_level
		subtaskQuery := bson.D{
			{Key: "group_id", Value: tasks[0].ID.Hex()},
		}
		var subtasks []model.ScanSubTasks
		err = e.MongoCli.FindAll((&model.ScanSubTasks{}).CollectName(), subtaskQuery, &subtasks)
		if err != nil {
			logger.Errorf("find baseline subtasks err:%v", err)
			continue
		}

		// Parse params to get risk_level
		for _, task := range subtasks {
			if params, ok := task.Params["risk_level"].(float64); ok {
				level := int32(params)
				switch level {
				case 2:
					result["high"]++
				case 3:
					result["medium"]++
				case 4, 5:
					result["low"]++
				}
			}
		}
	}

	return result, nil
}

// GetLeakCountsByLevel returns vulnerability counts by level from latest scan task
func GetLeakCountsByLevel(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)

	// Get latest leak scan task for each domain
	for _, domain := range domains {
		// Query latest leak scan task
		taskQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "type", Value: "leak"},
			{Key: "status", Value: "FINISH"},
		}

		var tasks []model.ScanTasks
		sort := bson.M{"create_tm": -1}
		err := e.MongoCli.FindSortByLimitAndSkip((&model.ScanTasks{}).CollectName(), taskQuery, sort, &tasks, 1, 0)
		if err != nil || len(tasks) == 0 {
			logger.Errorf("find leak tasks err:%v", err)
			continue
		}

		// Get subtasks for this scan task and count by risk_level
		subtaskQuery := bson.D{
			{Key: "group_id", Value: tasks[0].ID.Hex()},
		}
		var subtasks []model.ScanSubTasks
		err = e.MongoCli.FindAll((&model.ScanSubTasks{}).CollectName(), subtaskQuery, &subtasks)
		if err != nil {
			logger.Errorf("find leak subtasks err:%v", err)
			continue
		}

		// Parse params to get risk_level
		for _, task := range subtasks {
			if params, ok := task.Params["risk_level"].(float64); ok {
				level := int32(params)
				switch level {
				case 2:
					result["high"]++
				case 3:
					result["medium"]++
				case 4, 5:
					result["low"]++
				}
			}
		}
	}

	return result, nil
}

// GetWeakPwdCount returns total count of weak password detections
func GetWeakPwdCount(e *config.Env, domains []string) (int32, error) {
	var count int32

	for _, domain := range domains {
		// Query latest weakpwd scan task
		taskQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "type", Value: "weakpwd"},
			{Key: "status", Value: "FINISH"},
		}

		var tasks []model.ScanTasks
		sort := bson.M{"create_tm": -1}
		err := e.MongoCli.FindSortByLimitAndSkip((&model.ScanTasks{}).CollectName(), taskQuery, sort, &tasks, 1, 0)
		if err != nil || len(tasks) == 0 {
			logger.Errorf("find weakpwd tasks err:%v", err)
			continue
		}

		// Get subtasks count for this scan task
		subtaskQuery := bson.D{
			{Key: "group_id", Value: tasks[0].ID.Hex()},
		}
		total, err := e.MongoCli.FindCount((&model.ScanSubTasks{}).CollectName(), subtaskQuery)
		if err != nil {
			logger.Errorf("find weakpwd subtasks count err:%v", err)
			continue
		}

		count += int32(total)
	}

	return count, nil
}

// GetAssetCounts returns total asset count and today's new assets
func GetAssetCounts(e *config.Env, domains []string) (int32, int32, error) {
	var total int32
	var today int32

	// Calculate today's start time (00:00:00)
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	for _, domain := range domains {
		// Get total assets for this domain (users + computers)
		userQuery := bson.D{{Key: "domain", Value: domain}}
		userCount, err := e.MongoCli.FindCount((&model.AssetUser{}).CollectName(), userQuery)
		if err != nil {
			logger.Errorf("find user count err:%v", err)
		} else {
			total += int32(userCount)
		}

		computerQuery := bson.D{{Key: "domain", Value: domain}}
		computerCount, err := e.MongoCli.FindCount((&model.AssetComputer{}).CollectName(), computerQuery)
		if err != nil {
			logger.Errorf("find computer count err:%v", err)
		} else {
			total += int32(computerCount)
		}

		// Get today's new assets (created >= today 00:00:00)
		userTodayQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "create_tm", Value: bson.M{"$gte": todayStart}},
		}
		userTodayCount, err := e.MongoCli.FindCount((&model.AssetUser{}).CollectName(), userTodayQuery)
		if err != nil {
			logger.Errorf("find today user count err:%v", err)
		} else {
			today += int32(userTodayCount)
		}

		computerTodayQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "create_tm", Value: bson.M{"$gte": todayStart}},
		}
		computerTodayCount, err := e.MongoCli.FindCount((&model.AssetComputer{}).CollectName(), computerTodayQuery)
		if err != nil {
			logger.Errorf("find today computer count err:%v", err)
		} else {
			today += int32(computerTodayCount)
		}
	}

	return total, today, nil
}
