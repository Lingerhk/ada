package server

import (
	sCommon "ada/agent/sensor/common"
	"ada/backend/apiserver/config"
	"ada/backend/model"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
)

func GetSensorByID(e *config.Env, id string) (*model.Sensor, error) {
	sensor := model.Sensor{}
	query := bson.M{"_id": id}

	err, _ := e.MongoCli.FindOne(sensor.CollectName(), query, &sensor)
	if err != nil {
		logger.Errorf("get sensor err:%v", err)
		return nil, err
	}

	return &sensor, nil
}

func FindAllSensor(e *config.Env, keyword string, status, domain []string, limit, skip int64, tmSort int32) ([]model.Sensor, int64, error) {
	var agents []model.Sensor
	tb := (&model.Sensor{}).CollectName()

	query := bson.D{}
	if len(keyword) > 0 {
		var bm []bson.M
		bm = append(bm, bson.M{
			"ip": bson.M{"$regex": escaping(keyword), "$options": "i"},
		})
		bm = append(bm, bson.M{
			"dc_hostname": bson.M{"$regex": escaping(keyword), "$options": "i"},
		})

		query = append(query, bson.E{Key: "$or", Value: bm})
	}

	if len(status) > 0 {
		query = append(query, bson.E{Key: "status", Value: bson.M{"$in": status}})
	}

	if len(domain) > 0 {
		query = append(query, bson.E{Key: "domain", Value: bson.M{"$in": domain}})
	}

	total, err := e.MongoCli.FindCount(tb, query)
	if err != nil {
		return nil, 0, err
	}

	var sort = bson.M{"last_online_tm": tmSort}

	if err := e.MongoCli.FindSortByLimitAndSkip(tb, query, sort, &agents, limit, skip); err != nil {
		return nil, 0, err
	}
	return agents, total, nil
}

func UpdateSensorConf(e *config.Env, Id, remark string, bindNetIface []string, perfLimit, pluginSwitch map[string]string) error {
	var u model.Sensor

	update := bson.M{
		"remark":         remark,
		"bind_net_iface": bindNetIface,
		"perf_limit":     perfLimit,
		"status":         sCommon.SensorStatusRun,
	}
	for k, v := range pluginSwitch {
		update[k] = v
	}

	err := e.MongoCli.UpdateById(u.CollectName(), Id, &update)
	if err != nil {
		return err
	}
	return nil
}

func DeleteSensor(e *config.Env, Id string) error {
	var sensor model.Sensor

	err := e.MongoCli.RemoveById(sensor.CollectName(), Id)
	if err != nil {
		return err
	}
	return nil
}

func FindAllSensorByDomain(e *config.Env, domain string) ([]model.Sensor, error) {
	var sensors []model.Sensor
	tb := (&model.Sensor{}).CollectName()

	err := e.MongoCli.FindAll(tb, bson.M{"domain": domain}, &sensors)
	if err != nil {
		return nil, err
	}

	return sensors, nil
}

func GetSensorByDcHostName(e *config.Env, dcHostName string) (*model.Sensor, error) {
	var sensor model.Sensor
	tb := (&model.Sensor{}).CollectName()

	err, exist := e.MongoCli.FindOne(tb, bson.M{"dc_hostname": dcHostName}, &sensor)
	if err != nil || !exist {
		return nil, err
	}

	return &sensor, nil
}
