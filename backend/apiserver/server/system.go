package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	utime "ada/infra/time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func AddAuditLog(e *config.Env, userName, clientIP, event, eventArgs, eventResult string) error {
	var al model.AuditLog
	al.Username = userName
	al.ClientIp = clientIP
	al.EventArgs = eventArgs
	al.Event = event
	al.EventResult = eventResult
	al.CreateTm = utime.CurTime()

	err := e.MongoCli.Insert(al.CollectName(), &al)
	if err != nil {
		return err
	}

	return nil
}

func FindAllAuditLog(e *config.Env, query bson.D, sort bson.M, limit, offset int32) ([]model.AuditLog, int64, error) {
	var al []model.AuditLog
	tb := (&model.AuditLog{}).CollectName()
	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}
	err = e.MongoCli.FindWithMultiple(tb, query, nil, sort, &al, int64(limit), int64(offset))
	if err != nil {
		return nil, total, err
	}
	return al, total, nil
}

func GetSystemInfo(e *config.Env) (*model.SystemInfo, error) {
	var s model.SystemInfo
	err, exist := e.MongoCli.FindOne(s.CollectName(), bson.M{}, &s)
	if err != nil || !exist {
		return nil, err
	}

	return &s, nil
}

func UpdateProductIcon(e *config.Env, id primitive.ObjectID, iconB64 string) error {
	var sc model.SystemInfo
	query := bson.M{"_id": id}
	update := bson.M{"$set": bson.M{"product_icon": iconB64}}
	err := e.MongoCli.UpdateRaw(sc.CollectName(), query, &update, false)
	if err != nil {
		return err
	}
	return nil
}

func UpdateNtpAddress(e *config.Env, ntpAddress string) error {
	var sc model.SystemInfo

	update := bson.M{"$set": bson.M{"ntp_address": ntpAddress}}
	err := e.MongoCli.UpdateRaw(sc.CollectName(), bson.M{}, &update, false)
	if err != nil {
		return err
	}

	return nil
}

func UpdateLanguage(e *config.Env, lang string) error {
	var sc model.SystemInfo

	update := bson.M{"$set": bson.M{"system_language": lang}}
	err := e.MongoCli.UpdateRaw(sc.CollectName(), bson.M{}, &update, false)
	if err != nil {
		return err
	}

	return nil
}

func UpdateStatsCfg(e *config.Env, statsCfg map[string]string) error {
	var sc model.SystemInfo

	update := bson.M{"$set": bson.M{"stats_cfg": statsCfg}}
	err := e.MongoCli.UpdateRaw(sc.CollectName(), bson.M{}, &update, false)
	if err != nil {
		return err
	}

	return nil
}
