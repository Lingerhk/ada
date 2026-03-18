package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	utime "ada/infra/time"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func AddAuditLog(e *config.Env, userName, clientIP, event, eventArgs, eventResult string) error {
	var al model.AuditLog
	al.Username = userName
	al.ClientIp = clientIP
	al.EventArgs = eventArgs
	al.Event = event
	al.EventResult = eventResult
	al.CreateTm = utime.CurTime()

	err := e.MongoCli.Insert(e.MongoContext(), al.CollectName(), &al)
	if err != nil {
		return err
	}

	return nil
}

func FindAllAuditLog(e *config.Env, query bson.D, sort bson.M, limit, offset int32) ([]model.AuditLog, int64, error) {
	var al []model.AuditLog
	tb := (&model.AuditLog{}).CollectName()
	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}
	err = e.MongoCli.FindWithMultiple(e.MongoContext(), tb, query, nil, sort, &al, int64(limit), int64(offset))
	if err != nil {
		return nil, total, err
	}
	return al, total, nil
}

func GetSystemInfo(e *config.Env) (*model.SystemInfo, error) {
	var s model.SystemInfo
	err, exist := e.MongoCli.FindOne(e.MongoContext(), s.CollectName(), bson.M{}, &s)
	if err != nil || !exist {
		return nil, err
	}

	return &s, nil
}

func UpdateLanguage(e *config.Env, lang string) error {
	var sc model.SystemInfo

	update := bson.M{"$set": bson.M{"system_language": lang}}
	err := e.MongoCli.UpdateRaw(e.MongoContext(), sc.CollectName(), bson.M{}, &update, false)
	if err != nil {
		return err
	}

	return nil
}

// UpdateSystemCfg updates system configuration including ntp, systemIP, icon, upgradeSrv, and upgradeRule
func UpdateSystemCfg(e *config.Env, id bson.ObjectID, ntp, systemIP, file, upgradeSrv, upgradeRule string) error {
	var sc model.SystemInfo

	// Build update document with non-empty fields
	updateFields := bson.M{}
	if ntp != "" {
		updateFields["ntp_address"] = ntp
	}
	if systemIP != "" {
		updateFields["system_ip"] = systemIP
	}
	if file != "" {
		updateFields["system_icon"] = file
	}
	if upgradeSrv != "" {
		updateFields["upgrade_srv"] = upgradeSrv
	}
	if upgradeRule != "" {
		updateFields["upgrade_rule"] = (upgradeRule == "true")
	}

	// Only update if there are fields to update
	if len(updateFields) == 0 {
		return nil
	}

	update := bson.M{"$set": updateFields}
	err := e.MongoCli.UpdateRaw(e.MongoContext(), sc.CollectName(), bson.M{}, &update, false)
	if err != nil {
		return err
	}

	return nil
}

// UpdateSystemProxy updates system proxy configuration
func UpdateSystemProxy(e *config.Env, httpProxy, httpsProxy string, upgradeProxy, notifyProxy bool) error {
	var sc model.SystemInfo

	// Build system proxy map
	systemProxy := map[string]string{
		"http_proxy":    httpProxy,
		"https_proxy":   httpsProxy,
		"upgrade_proxy": boolToString(upgradeProxy),
		"notify_proxy":  boolToString(notifyProxy),
	}

	update := bson.M{"$set": bson.M{"system_proxy": systemProxy}}
	err := e.MongoCli.UpdateRaw(e.MongoContext(), sc.CollectName(), bson.M{}, &update, false)
	if err != nil {
		return err
	}

	return nil
}

func UpdateStatsCfg(e *config.Env, statsCfg map[string]string) error {
	var sc model.SystemInfo

	update := bson.M{"$set": bson.M{"stats_cfg": statsCfg}}
	err := e.MongoCli.UpdateRaw(e.MongoContext(), sc.CollectName(), bson.M{}, &update, false)
	if err != nil {
		return err
	}

	return nil
}

// FindAllSystemLogs retrieves and filters system logs from MongoDB
func FindAllSystemLogs(env *config.Env, levels []string, modules []string, search string, startTm, endTm string, sortTime int32, limit, skip int32) ([]model.SystemLogs, int64, error) {
	// Build MongoDB query filter
	filter := bson.M{}

	// Add module filter
	if len(modules) > 0 {
		filter["module"] = bson.M{"$in": modules}
	}

	// Add level filter
	if len(levels) > 0 {
		filter["level"] = bson.M{"$in": levels}
	}

	// Add search filter (search in msg field)
	if search != "" {
		filter["msg"] = bson.M{"$regex": search, "$options": "i"} // case-insensitive
	}

	// Add time range filter
	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err == nil {
			filter["time"] = bson.M{
				"$gte": startTime,
				"$lte": endTime,
			}
		}
	}

	// Build sort order
	sortOrder := -1 // Default: descending (newest first)
	if sortTime == 1 {
		sortOrder = 1 // Ascending (oldest first)
	}

	// Query MongoDB - use intermediate struct with time.Time for BSON deserialization
	type mongoSystemLog struct {
		Time   time.Time `bson:"time"`
		Level  string    `bson:"level"`
		Module string    `bson:"module"`
		Msg    string    `bson:"msg"`
		Func   string    `bson:"func"`
		File   string    `bson:"file"`
	}

	var mongoLogs []mongoSystemLog
	tb := (&model.SystemLogs{}).CollectName()
	err := env.MongoCli.FindSortByLimitAndSkip(env.MongoContext(),
		tb,
		filter,
		bson.M{"time": sortOrder},
		&mongoLogs,
		int64(limit),
		int64(skip),
	)
	if err != nil {
		return nil, 0, err
	}

	// Get total count
	total, err := env.MongoCli.FindCount(env.MongoContext(), tb, filter)
	if err != nil {
		return nil, 0, err
	}

	// Convert to SystemLogs format for API response
	var result []model.SystemLogs
	for _, log := range mongoLogs {
		result = append(result, model.SystemLogs{
			Time:   log.Time.Format(time.RFC3339),
			Level:  log.Level,
			Module: log.Module,
			Msg:    log.Msg,
			Func:   log.Func,
			File:   log.File,
		})
	}

	return result, total, nil
}
