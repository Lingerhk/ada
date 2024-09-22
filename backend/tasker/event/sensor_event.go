package event

import (
	sCommon "ada/agent/sensor/common"
	"ada/backend/cache"
	"ada/backend/model"
	"ada/infra/mongo"
	"context"
	"encoding/json"
	"fmt"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"strconv"
	"time"
)

type SensorEvent struct {
	redisCli *redis.Client
	mongoCli mongo.DBAdaptor
}

func NewSensorEvent(redisCli *redis.Client, mongoCli mongo.DBAdaptor) *SensorEvent {
	return &SensorEvent{redisCli: redisCli, mongoCli: mongoCli}
}

func (s *SensorEvent) Process(msg string) {
	var msgJson sCommon.AdaMessage

	if err := json.Unmarshal([]byte(msg), &msgJson); err != nil {
		logger.Warnf("json unmarshal msg err:%v", err)
		return
	}

	switch msgJson.MsgType {
	case sCommon.T_CMD_SENSOR_REG:
		s.register(msgJson)
	case sCommon.T_CONF_STATE:
		s.state(msgJson)
	default:
		logger.Errorf("invalid msg_type:%d from sensor_id:%s", msgJson.MsgType, msgJson.AgentID)
		return
	}
}

func (s *SensorEvent) register(regMsg sCommon.AdaMessage) {
	ctx := context.Background()

	// check reg_code
	// TODO: pass
	_, ok := regMsg.Data["reg_code"]
	if !ok {
		logger.Warningf("get reg_code form sensor(%s) register msg failed, will ignore this register msg", regMsg.AgentID)
		s.cmdResp(ctx, regMsg.TaskID, regMsg.AgentID, "get reg_code failed")
		return
	}

	// check sensor_id already exist
	sensor := model.Sensor{}
	query := bson.M{"_id": regMsg.AgentID}
	err, _ := s.mongoCli.FindOne(sensor.CollectName(), query, &sensor)
	if err == nil {
		logger.Warnf("sensor(%s) already exist, will ignore this register msg", regMsg.AgentID)
		s.cmdResp(ctx, regMsg.TaskID, regMsg.AgentID, "sensor already exist")
		return
	}

	if err != mongo.ErrNotFound {
		logger.Errorf("get sensor(%s) err:%v", regMsg.AgentID, err)
		s.cmdResp(ctx, regMsg.TaskID, regMsg.AgentID, err.Error())
		return
	}

	var cardInfo map[string]string
	err = json.Unmarshal([]byte(regMsg.Data["net_iface"]), &cardInfo)
	if err != nil {
		logger.Errorf("json unmarshal cardInfo err:%v", err)
		s.cmdResp(ctx, regMsg.TaskID, regMsg.AgentID, err.Error())
		return
	}

	// insert sensor info
	sensor.ID = regMsg.AgentID
	sensor.IP, _ = regMsg.Data["ip"]
	sensor.Version = regMsg.Version
	sensor.Timestamp = strconv.FormatInt(regMsg.Timestamp, 10)
	sensor.Domain, _ = regMsg.Data["domain"]
	sensor.DCHostName, _ = regMsg.Data["dc_hostname"]
	sensor.Platform, _ = regMsg.Data["platform"]
	sensor.KernelVer, _ = regMsg.Data["kernel_version"]
	sensor.Status = sCommon.SensorStatusInit
	sensor.Remark = "--"
	sensor.MemTotal, _ = regMsg.Data["mem_total"]
	sensor.CpuTotal, _ = regMsg.Data["cpu_total"]
	sensor.NetIface = cardInfo
	sensor.BindNetIface = []string{"0"}
	sensor.DcIntervalTm = time.Now().Unix() - regMsg.Timestamp
	sensor.PktStatus = sCommon.SensorStatusInit
	sensor.LogStatus = sCommon.SensorStatusInit

	sensor.PktPluginSwitch = "false"
	sensor.LogPluginSwitch = "false"
	sensor.RpcFwPluginSwitch = "false"
	sensor.LdapFwPluginSwitch = "false"
	sensor.PktPluginStatus = sCommon.SensorStatusInit
	sensor.LogPluginStatus = sCommon.SensorStatusInit
	sensor.RpcFwPluginStatus = sCommon.SensorStatusInit
	sensor.LdapFwPluginStatus = sCommon.SensorStatusInit
	sensor.PktCpuUsed = "0%"
	sensor.PktMemUsed = "0%"
	sensor.LogCpuUsed = "0%"
	sensor.LogMemUsed = "0%"
	sensor.RpcFwCpuUsed = "0%"
	sensor.RpcFwMemUsed = "0%"
	sensor.LdapFwCpuUsed = "0%"
	sensor.LdapFwMemUsed = "0%"

	sensor.PerfLimit = map[string]string{"limit_mem_max": "0.05", "limit_cpu_max": "0.05"}
	sensor.Events = []map[string]string{}
	sensor.CreateTm = time.Now()
	sensor.LastOnlineTm = time.Now()
	sensor.LastCollectTm = time.Now()

	err = s.mongoCli.Insert(sensor.CollectName(), &sensor)
	if err != nil {
		logger.Errorf("create sensor err:%v", err)
		s.cmdResp(ctx, regMsg.TaskID, regMsg.AgentID, err.Error())
		return
	}

	// add sensor info into redis hash
	sensorInfo := make(map[string]interface{})
	sensorInfo["version"] = sensor.Version
	sensorInfo["ip"] = sensor.IP
	sensorInfo["domain"] = sensor.Domain
	sensorInfo["timestamp"] = sensor.Timestamp
	sensorInfo["dc_hostname"] = sensor.DCHostName
	sensorInfo["pkt_plugin_switch"] = sensor.PktPluginSwitch
	sensorInfo["log_plugin_switch"] = sensor.LogPluginSwitch
	sensorInfo["rpcfw_plugin_switch"] = sensor.RpcFwPluginSwitch
	sensorInfo["ldapfw_plugin_switch"] = sensor.LdapFwPluginSwitch
	sensorInfo["ldapfw_plugin_switch"] = sensor.LdapFwPluginSwitch
	sensorInfo["limit_mem_max"] = "0.05"
	sensorInfo["limit_cpu_max"] = "0.05"
	sensorInfo["bind_net_iface"] = "0"
	sensorInfo["last_online_tm"] = sensor.LastOnlineTm

	err = s.redisCli.HMSet(ctx, cache.SensorIDKey(sensor.ID), sensorInfo).Err()
	if err != nil {
		logger.Errorf("set sensor info into redis err:%v", err)
		s.cmdResp(ctx, regMsg.TaskID, regMsg.AgentID, err.Error())
		return
	}

	// resp cmd to sensor side
	s.cmdResp(ctx, regMsg.TaskID, regMsg.AgentID, "")

	logger.Infof("handle sensor(%s) register succed", regMsg.AgentID)
}

func (s *SensorEvent) cmdResp(ctx context.Context, taskId, sensorId, msg string) {
	// redis 指定的key中写入结果
	result := map[string]string{"succeed": "1", "sensor_id": sensorId, "msg": msg, "timestamp": strconv.FormatInt(time.Now().Unix(), 10)}
	if msg != "" {
		result["succeed"] = "0"
	}

	taskKey := fmt.Sprintf("%s_%s", sCommon.SensorCmdRespKey, taskId)
	err := s.redisCli.HMSet(ctx, taskKey, result).Err()
	if err != nil {
		logger.Errorf("redis set task_info err:%v", err)
		return
	}
	err = s.redisCli.Expire(ctx, taskKey, 3600*time.Second).Err()
	if err != nil {
		logger.Errorf("redis set task_info ttl err:%v", err)
		return
	}
}

func (s *SensorEvent) state(stateMsg sCommon.AdaMessage) {
	ctx := context.Background()

	// check sensor_id exist
	sensor := model.Sensor{}
	query := bson.M{"_id": stateMsg.AgentID}
	err, _ := s.mongoCli.FindOne(sensor.CollectName(), query, &sensor)
	if err != nil {
		if err == mongo.ErrNotFound {
			logger.Warnf("sensor(%s) does not exist, will ignore this state msg", stateMsg.AgentID)
			return
		}
		logger.Warnf("get sensor(%s) err:%v", stateMsg.AgentID, err)
		return
	}

	sensor.Version = stateMsg.Version
	sensor.Status, _ = stateMsg.Data["status"]

	var cardInfo map[string]string
	err = json.Unmarshal([]byte(stateMsg.Data["net_iface"]), &cardInfo)
	if err != nil {
		logger.Errorf("json unmarshal cardInfo err:%v", err)
		return
	}
	sensor.NetIface = cardInfo
	sensor.Timestamp = strconv.FormatInt(stateMsg.Timestamp, 10)

	sensor.MemTotal, _ = stateMsg.Data["mem_total"]
	sensor.CpuTotal, _ = stateMsg.Data["cpu_total"]
	sensor.PktCpuUsed, _ = stateMsg.Data["pkt_cpu_used"]
	sensor.PktMemUsed, _ = stateMsg.Data["pkt_mem_used"]
	sensor.LogCpuUsed, _ = stateMsg.Data["log_cpu_used"]
	sensor.LogMemUsed, _ = stateMsg.Data["log_mem_used"]
	sensor.RpcFwCpuUsed, _ = stateMsg.Data["rpcfw_cpu_used"]
	sensor.RpcFwMemUsed, _ = stateMsg.Data["rpcfw_mem_used"]
	sensor.LdapFwCpuUsed, _ = stateMsg.Data["ldapfw_cpu_used"]
	sensor.LdapFwMemUsed, _ = stateMsg.Data["ldapfw_mem_used"]
	sensor.LdapFwMemUsed, _ = stateMsg.Data["ldapfw_mem_used"]
	sensor.LdapFwMemUsed, _ = stateMsg.Data["ldapfw_mem_used"]

	if val, ok := stateMsg.Data["pkt_status"]; ok {
		sensor.PktStatus = val
		sensor.PktPluginStatus = val
	}
	if val, ok := stateMsg.Data["log_status"]; ok {
		sensor.LogStatus = val
		sensor.LogPluginStatus = val
	}
	if val, ok := stateMsg.Data["rpcfw_status"]; ok {
		sensor.RpcFwPluginStatus = val
	}
	if val, ok := stateMsg.Data["ldapfw_status"]; ok {
		sensor.LdapFwPluginStatus = val
	}

	sensor.LastOnlineTm = time.Unix(stateMsg.Timestamp, 0)
	sensor.LastCollectTm = time.Unix(stateMsg.Timestamp, 0)

	err = s.mongoCli.Update(sensor.CollectName(), &query, &sensor, false)
	if err != nil {
		logger.Warnf("update sensor(%s) err:%v", stateMsg.AgentID, err)
		return
	}

	// update redis cache
	sensorInfo := make(map[string]interface{})
	sensorInfo["version"] = sensor.Version
	sensorInfo["timestamp"] = sensor.Timestamp
	sensorInfo["last_online_tm"] = sensor.LastOnlineTm
	err = s.redisCli.HMSet(ctx, cache.SensorIDKey(sensor.ID), sensorInfo).Err()
	if err != nil {
		logger.Errorf("set sensor info into redis err:%v", err)
		return
	}

	logger.Infof("handle sensor(%s) state succed", stateMsg.AgentID)
}
