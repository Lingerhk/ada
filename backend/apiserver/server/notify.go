package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"time"
)

func FindAllNotify(env *config.Env, msgType []string, status []int32, startTm, endTm string, sortTime, limit, skip int32) ([]model.Notify, int64, error) {
	var notifyList []model.Notify
	tb := (&model.Notify{}).CollectName()

	query := bson.D{}
	if len(msgType) > 0 {
		query = append(query, bson.E{Key: "msg_type", Value: bson.D{{"$in", msgType}}})
	}
	if len(status) > 0 {
		query = append(query, bson.E{Key: "status", Value: bson.D{{"$in", status}}})
	}
	if startTm != "" && endTm != "" {
		startTime, endTime, err := initTimeInterval(startTm, endTm)
		if err != nil {
			return nil, 0, err
		}
		query = append(query, bson.E{Key: "create_tm", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8)}})
	}

	sort := bson.M{}
	if sortTime != 0 {
		sort["create_tm"] = sortTime
	}

	count, err := env.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	err = env.MongoCli.FindSortByLimitAndSkip(tb, query, sort, &notifyList, int64(limit), int64(skip))
	if err != nil {
		return nil, 0, err
	}
	return notifyList, count, nil
}

func UpdateNotifyStatus(env *config.Env, IDs []string) error {
	n := model.Notify{}
	query := bson.M{}
	for _, ID := range IDs {
		Id, err := primitive.ObjectIDFromHex(ID)
		if err != nil {
			return err
		}
		query["_id"] = Id
		updateM := bson.M{"$set": bson.M{"status": 1}}
		err = env.MongoCli.UpdateRaw(n.CollectName(), &query, &updateM, false)
		if err != nil {
			return err
		}
	}
	return nil
}

func FindAllNotifyConf(env *config.Env, moduleType, notifyType []string, target string, enable []string, sortTime, limit, skip int32) ([]model.NotifyConf, int64, error) {
	var confList []model.NotifyConf
	tb := (&model.NotifyConf{}).CollectName()

	query := bson.M{}
	if len(moduleType) > 0 {
		query["module_name"] = bson.M{"$in": moduleType}
	}
	if len(notifyType) > 0 {
		query["notify_type"] = bson.M{"$in": notifyType}
	}
	if target != "" {
		query["endpoint"] = bson.M{"$regex": escaping(target)}
	}
	if len(enable) > 0 {
		query["enable"] = bson.M{"$in": enable}
	}

	sort := bson.M{}
	if sortTime != 0 {
		sort["update_tm"] = sortTime
	}

	count, err := env.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	err = env.MongoCli.FindSortByLimitAndSkip(tb, query, sort, &confList, int64(limit), int64(skip))
	if err != nil {
		return nil, 0, err
	}
	return confList, count, nil
}

func GetNotifyConf(e *config.Env, id string) (*model.NotifyConf, error) {
	var s model.NotifyConf

	Id, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	err, exist := e.MongoCli.FindOne(s.CollectName(), bson.M{"_id": Id}, &s)
	if err != nil || !exist {
		return nil, err
	}

	return &s, nil
}

func UpdateNotifyConf(e *config.Env, nc *model.NotifyConf) error {
	query := bson.M{"_id": nc.ID}
	err := e.MongoCli.Update(nc.CollectName(), &query, &nc, false)
	if err != nil {
		return err
	}
	return nil
}
