package worker

import (
	sCommon "ada/agent/sensor/common"
	"ada/backend/cache"
	"ada/infra/mongo"
	"context"
	"encoding/json"
	"fmt"
	"go.mongodb.org/mongo-driver/bson"
	"strconv"
	"strings"
	"time"

	"ada/backend/common"
	"ada/backend/model"
	"ada/backend/tasker/config"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

func (w *Worker) SystemNotifyTask() error {
	ctx := context.Background()

	var s model.SystemInfo
	err, exist := w.env.MongoCli.FindOne(s.CollectName(), bson.M{}, &s)
	if err != nil {
		return err
	}
	if !exist {
		return fmt.Errorf("system info not found")
	}
	statsCfg := make(map[string]float64)
	for k, v := range s.StatsCfg {
		if v == "" {
			continue
		}
		value, err := strconv.ParseFloat(v, 64)
		if err != nil {
			logger.Errorf("parse into float64(val:%s) err:%v", v, err)
			continue
		}
		statsCfg[k] = value
	}

	if err := checkSystemStatusCPU(ctx, w.env, statsCfg); err != nil {
		logger.Warnf("check ststem status(CPU) err:%v", err)
	}

	if err := checkSystemStatusMem(ctx, w.env, statsCfg); err != nil {
		logger.Warnf("check ststem status(Mem) err:%v", err)
	}

	if err := checkSystemStatusDisk(ctx, w.env, statsCfg); err != nil {
		logger.Warnf("check ststem status(Disk) err:%v", err)
	}

	if err := checkSystemStatusES(ctx, w.env, statsCfg); err != nil {
		logger.Warnf("check ststem status(ES) err:%v", err)
	}

	if err := checkSystemStatusSensor(ctx, w.env, statsCfg); err != nil {
		logger.Warnf("check ststem status(Sensor) err:%v", err)
	}

	return nil
}

func checkSystemStatusCPU(ctx context.Context, env *config.Env, statsCfg map[string]float64) error {
	// 直接读system_sync的 redis cache
	cpu, err := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "cpu_percent").Result()
	if err != nil {
		return err
	}
	cpuPercent, err := strconv.ParseFloat(cpu, 32)
	if err != nil {
		return err
	}

	threshold, ok := statsCfg["cpu_percent_notify"]
	if !ok {
		threshold = 85.0
	}

	if cpuPercent > threshold {
		load15m := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "local_15m").Val()
		title := fmt.Sprintf("%s:%s", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem], "系统CPU占用率过高")
		params := map[string]string{"cpu_percent": cpu, "load_15m": load15m, "threshold": fmt.Sprintf("%.1f", threshold)}
		err = AddNotify(env.MongoCli, title, "cpu", fmt.Sprintf("CPU占用率超过%.1f%%", threshold), params)
	}

	return err
}

func checkSystemStatusMem(ctx context.Context, env *config.Env, statsCfg map[string]float64) error {
	// 直接读system_sync的 redis cache
	mem, err := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "mem_percent").Result()
	if err != nil {
		return err
	}
	memPercent, err := strconv.ParseFloat(mem, 32)
	if err != nil {
		return err
	}

	threshold, ok := statsCfg["mem_percent_notify"]
	if !ok {
		threshold = 90.0
	}

	if memPercent > threshold {
		memTotal := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "mem_total").Val()
		title := fmt.Sprintf("%s:%s", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem], "系统MEM占用率过高")
		params := map[string]string{"mem_percent": mem, "mem_total": memTotal, "threshold": fmt.Sprintf("%.1f", threshold)}
		err = AddNotify(env.MongoCli, title, "mem", fmt.Sprintf("MEM占用率超过%.1f%%", threshold), params)
	}

	return err
}

func checkSystemStatusDisk(ctx context.Context, env *config.Env, statsCfg map[string]float64) error {
	// 直接读system_sync的 redis cache
	disk, err := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "disk_percent").Result()
	if err != nil {
		return err
	}
	diskPercent, err := strconv.ParseFloat(disk, 32)
	if err != nil {
		return err
	}

	threshold, ok := statsCfg["disk_percent_notify"]
	if !ok {
		threshold = 90.0
	}

	if diskPercent > threshold {
		diskTotal := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "disk_total").Val()
		title := fmt.Sprintf("%s:%s", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem], "系统Disk占用率过高")
		params := map[string]string{"disk_percent": disk, "disk_total": diskTotal, "threshold": fmt.Sprintf("%.1f", threshold)}
		err = AddNotify(env.MongoCli, title, "disk", fmt.Sprintf("Disk占用率超过%.1f%%", threshold), params)
	}

	return err
}

func checkSystemStatusES(ctx context.Context, env *config.Env, statsCfg map[string]float64) error {
	// 直接读system_sync的 redis cache

	// Check ES Disk usage
	esDisk, err := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "es_disk_percent").Result()
	if err != nil {
		return err
	}
	esDiskPercent, err := strconv.ParseFloat(esDisk, 32)
	if err != nil {
		return err
	}

	threshold, ok := statsCfg["es_disk_percent_notify"]
	if !ok {
		threshold = 85.0
	}

	if esDiskPercent > threshold {
		esDiskAvail := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "es_disk_avail").Val()
		esDiskTotal := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "es_disk_total").Val()
		title := fmt.Sprintf("%s:%s", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem], "系统ES组件磁盘占用率过高")
		params := map[string]string{"es_disk_percent": esDisk, "es_disk_total": esDiskTotal, "es_disk_avail": esDiskAvail, "threshold": fmt.Sprintf("%.1f", threshold)}
		err = AddNotify(env.MongoCli, title, "es", fmt.Sprintf("ES组件磁盘占用率超过%.1f%%", threshold), params)
	}

	// Check ES CPU usage
	esCpu, err := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "es_cpu_percent").Result()
	if err != nil {
		return err
	}

	esCpuPercent, err := strconv.ParseFloat(esCpu, 32)
	if err != nil {
		return err
	}

	threshold, ok = statsCfg["es_cpu_percent_notify"]
	if !ok {
		threshold = 85.0
	}

	if esCpuPercent > threshold {
		esSysLoad1m := env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "es_sys_load1m").Val()
		title := fmt.Sprintf("%s:%s", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem], "系统ES组件CPU占用率过高")
		params := map[string]string{"es_cpu_percent": esCpu, "es_sys_load1m": esSysLoad1m, "threshold": fmt.Sprintf("%1.f", threshold)}
		err = AddNotify(env.MongoCli, title, "es", fmt.Sprintf("ES组件CPU占用率超过%1f%%", threshold), params)
	}

	return err
}

// checkSystemStatusSensor: 检查Sensor最近在线时间&检查日志/流量最后采集时间
func checkSystemStatusSensor(ctx context.Context, env *config.Env, statsCfg map[string]float64) error {
	sensorKeys, err := env.RedisCli.Keys(ctx, "ada:sensor:id:*").Result()
	if err != nil {
		logger.Errorf("redis get err:%v", err)
		return err
	}

	for _, sensorKey := range sensorKeys {
		info, err := env.RedisCli.HGetAll(ctx, sensorKey).Result()
		if err != nil {
			logger.Warnf("redis hgetall(%s) err:%v", sensorKey, err)
			continue
		}

		currentTs := time.Now().Unix()

		// 检查sensor最后在线时间
		if lastOnlineTm, ok := info["last_online_tm"]; ok {
			parsedTm, err := time.Parse(time.RFC3339, lastOnlineTm)
			if err != nil {
				logger.Warnf("parse last_online_tm err:%v", err)
				continue
			}

			// sensor超过20分钟没有上报stats，则notify。 6小时内不再重复提醒
			if currentTs-parsedTm.Unix() > 1200 {
				lastNotifyKey := fmt.Sprintf("ada:server:notify_ttl_sensor_1_%s", sensorKey)
				// 更新sensor状态
				err = updateSensorStatus(env.MongoCli, sensorKey, sCommon.SensorStatusStop)
				if err != nil {
					logger.Warnf("update sensor status err:%v", err)
				}

				// 发送告警通知
				if env.RedisCli.Exists(ctx, lastNotifyKey).Val() == 0 {
					title := fmt.Sprintf("%s:传感器状态异常", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem])
					params := map[string]string{"last_online_tm": lastOnlineTm, "dc_hostname": info["dc_hostname"], "ip": info["ip"]}
					err = AddNotify(env.MongoCli, title, "sensor", "传感器状态异常", params)
					if err == nil {
						if err := env.RedisCli.Set(ctx, lastNotifyKey, "1", 6*time.Hour).Err(); err != nil {
							logger.Warnf("redis set sensor notify last_tm key err:%v", err)
						}
					}
				}
			}
		}

		// sensor 时间校验, 传感器时间与服务器时间相差超过2min则notify
		if sensorTimestampStr, ok := info["timestamp"]; ok {
			sensorTimestamp, err := strconv.ParseInt(sensorTimestampStr, 10, 64)
			if err != nil {
				logger.Warnf("parse sensor timestamp err:%v", err)
				continue
			}

			ts := time.Unix(sensorTimestamp, 0).Unix()
			if currentTs-ts > 120 || currentTs-ts < -120 {
				lastNotifyKey := fmt.Sprintf("ada:server:notify_ttl_sensor_6_%s", sensorKey)
				if env.RedisCli.Exists(ctx, lastNotifyKey).Val() == 0 {
					title := fmt.Sprintf("%s:传感器时间异常", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem])
					params := map[string]string{"dc_hostname": info["dc_hostname"], "ip": info["ip"], "sensor_timestamp": sensorTimestampStr, "system_timestamp": strconv.FormatInt(currentTs, 10)}
					err = AddNotify(env.MongoCli, title, "sensor", "传感器时间异常", params)
					if err == nil {
						if err := env.RedisCli.Set(ctx, lastNotifyKey, "1", 6*time.Hour).Err(); err != nil {
							logger.Warnf("redis set sensor notify sensor_timestamp key err:%v", err)
						}
					}
				}
			}
		}

		// 说明：SensorCollectStatusKey 是redis中存储sensor采集状态，其来源为receiver 和 engine
		// receiver中以 rawpkt_dcHostname 和 winlog_dcHostname 为key，记录最后一次收到数据的时间戳 (暂时不会用该值，但debug时可以用)
		// engine中以 winlog_dcHostname 和 pktlog_dcHostname 为key，记录最后一次收到数据的时间戳

		// 检查sensor采集的最后在线时间
		dcHostname := fmt.Sprintf("%s.%s", info["dc_hostname"], info["domain"])
		if info["log_plugin_switch"] == "true" {
			lastTm := env.RedisCli.HGet(ctx, cache.SensorCollectStatusKey, "winlog_"+dcHostname).Val()
			if lastTm == "" {
				lastNotifyKey := fmt.Sprintf("ada:server:notify_ttl_sensor_2_%s", sensorKey)
				if env.RedisCli.Exists(ctx, lastNotifyKey).Val() == 0 {
					title := fmt.Sprintf("%s:传感器日志未采集", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem])
					params := map[string]string{"dc_hostname": info["dc_hostname"], "ip": info["ip"], "sensor_last_online": info["last_online_tm"]}
					err = AddNotify(env.MongoCli, title, "sensor", "传感器日志采集状态异常", params)
					if err == nil {
						if err := env.RedisCli.Set(ctx, lastNotifyKey, "1", 6*time.Hour).Err(); err != nil {
							logger.Warnf("redis set sensor notify last_tm key err:%v", err)
						}
					}
				}
			} else {
				ts, err := strconv.ParseInt(lastTm, 10, 64)
				if err != nil {
					logger.Warnf("parse last timestamp err:%v", err)
					continue
				}

				// 超过60分钟未上传日志
				if currentTs-ts > 3600 {
					lastNotifyKey := fmt.Sprintf("ada:server:notify_ttl_sensor_3_%s", sensorKey)
					if env.RedisCli.Exists(ctx, lastNotifyKey).Val() == 0 {
						title := fmt.Sprintf("%s:传感器日志采集异常", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem])
						params := map[string]string{"dc_hostname": info["dc_hostname"], "ip": info["ip"], "last_collect_tm": time.Unix(ts, 0).String()}
						err = AddNotify(env.MongoCli, title, "sensor", "传感器日志采集状态异常", params)
						if err == nil {
							if err := env.RedisCli.Set(ctx, lastNotifyKey, "1", 6*time.Hour).Err(); err != nil {
								logger.Warnf("redis set sensor notify last_tm key err:%v", err)
							}
						}
					}
				}
			}
		}
		if info["pkg_plugin_switch"] == "true" {
			// TODO: 待receiver端实现: rawpkt_dcHostname heartbeat
			lastTm := env.RedisCli.HGet(ctx, cache.SensorCollectStatusKey, "pktlog_"+dcHostname).Val()
			if lastTm == "" {
				lastNotifyKey := fmt.Sprintf("ada:server:notify_ttl_sensor_4_%s", sensorKey)
				if env.RedisCli.Exists(ctx, lastNotifyKey).Val() == 0 {
					title := fmt.Sprintf("%s:传感器流量未采集", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem])
					params := map[string]string{"dc_hostname": info["dc_hostname"], "ip": info["ip"], "sensor_last_online": info["last_online_tm"]}
					err = AddNotify(env.MongoCli, title, "sensor", "传感器流量采集状态异常", params)
					if err == nil {
						if err := env.RedisCli.Set(ctx, lastNotifyKey, "1", 6*time.Hour).Err(); err != nil {
							logger.Warnf("redis set sensor notify last_tm key err:%v", err)
						}
					}
				}
			} else {
				ts, err := strconv.ParseInt(lastTm, 10, 64)
				if err != nil {
					logger.Warnf("parse last timestamp err:%v", err)
					continue
				}

				// 超过60分钟未上传流量
				if currentTs-ts > 3600 {
					lastNotifyKey := fmt.Sprintf("ada:server:notify_ttl_sensor_5_%s", sensorKey)
					if env.RedisCli.Exists(ctx, lastNotifyKey).Val() == 0 {
						title := fmt.Sprintf("%s:传感器日志采集异常", common.NotifyMsgTypeDescMap[common.NotifyMsgSystem])
						params := map[string]string{"dc_hostname": info["dc_hostname"], "ip": info["ip"], "last_collect_tm": time.Unix(ts, 0).String()}
						err = AddNotify(env.MongoCli, title, "sensor", "传感器流量采集状态异常", params)
						if err == nil {
							if err := env.RedisCli.Set(ctx, lastNotifyKey, "1", 6*time.Hour).Err(); err != nil {
								logger.Warnf("redis set sensor notify last_tm key err:%v", err)
							}
						}
					}
				}
			}
		}
	}

	return nil
}

func updateSensorStatus(mongoCli mongo.DBAdaptor, sensorKey, status string) error {
	var s model.Sensor

	// sensorKey: ada:sensor:id:ac858538-4a4d-4c23-8725-2d607aaf0efb
	parts := strings.SplitN(sensorKey, ":id:", 2)
	if len(parts) != 2 || len(parts[1]) != 36 {
		return fmt.Errorf("invalid sensor key(%s)", sensorKey)
	}

	err, exist := mongoCli.FindOne(s.CollectName(), bson.M{"_id": parts[1]}, &s)
	if err != nil || !exist {
		return err
	}

	update := bson.M{
		"status": status,
	}

	err = mongoCli.UpdateById(s.CollectName(), s.ID, &update)
	if err != nil {
		logger.Errorf("update sensor statusid(%s) err:%v", s.ID, err)
		return err
	}

	return nil
}

func AddNotify(mongoCli mongo.DBAdaptor, title, eventType, desc string, params map[string]string) error {
	notify := model.Notify{
		ID:        primitive.NewObjectID(),
		Title:     title,
		MsgType:   common.NotifyMsgSystem,
		EventType: eventType,
		Desc:      desc,
		Params:    params,
		CreateTm:  time.Now(),
	}

	err := mongoCli.Insert(notify.CollectName(), &notify)
	if err != nil {
		logger.Errorf("insert notify err :%v", err)
		return err
	}

	var notifyMsg notifyInfo
	notifyMsg.Title = notify.Title
	notifyMsg.Desc = desc
	notifyMsg.MsgType = common.NotifyMsgSystem
	notifyMsg.EventType = eventType
	notifyMsg.Params = params
	notifyMsg.Timestamp = notify.CreateTm.Unix()

	notifyByte, _ := json.Marshal(notifyMsg)

	confList, err := getNotifyConfs(mongoCli, common.NotifyMsgSystem)
	if err != nil {
		logger.Errorf("get notify conf(system) err:%v", err)
		return err
	}

	for _, conf := range confList {
		if conf.Enable == "disable" {
			continue
		}
		if conf.Endpoint == "" {
			logger.Warnf("ingore notify type(%s) becasue endpoint is empty!", conf.NotifyType)
			continue
		}

		switch conf.NotifyType {
		case "email":
			err = sendEmailNotify(notifyMsg, conf)
		case "syslog":
			err = sendSyslogNotify(string(notifyByte), conf)
		case "webhook":
			err = sendWebhookNotify(string(notifyByte), conf)
		default:
			logger.Errorf("invalid notify_type(%s), will igore this nofity", conf.NotifyType)
			return fmt.Errorf("invalid notify_type(%s), will igore this nofity", conf.NotifyType)
		}

		if err != nil {
			logger.Errorf("send notify_type(%s) err:%v", conf.NotifyType, err)
		}
	}

	return nil
}
