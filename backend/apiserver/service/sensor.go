package service

import (
	sCommon "ada/agent/sensor/common"
	v2 "ada/backend/apiserver/api/v2"
	aCommon "ada/backend/apiserver/common"
	"ada/backend/apiserver/server"
	"ada/backend/cache"
	"ada/backend/common"
	"ada/infra/version"
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ADAServiceV2) ListSensor(ctx context.Context, in *v2.ListSensorReq) (*v2.ListSensorReply, error) {
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	sensorList, total, err := server.FindAllSensor(s.env, in.Keyword, in.Status, in.Domain, int64(limit), int64(offset), in.TmSort)
	if err != nil {
		logger.Errorf("query ListSensor err:%v", err)
		return nil, status.Errorf(codes.Internal, "查询失败")
	}

	newVer, err := s.getSensorVersion()
	if err != nil {
		logger.Warnf("query ListAgent err:%v", err)
	}

	ret := v2.ListSensorReply{}
	for _, sensor := range sensorList {
		var events []*v2.ListSensorReplyMapSlice
		for _, v := range sensor.Events {
			events = append(events, &v2.ListSensorReplyMapSlice{Event: v})
		}

		// 计算域控时间
		var sensorTime string
		if sensor.DcIntervalTm >= 0 {
			sensorTime = time.Unix(time.Now().Unix()-sensor.DcIntervalTm, 0).UTC().String()
		} else {
			sensorTime = time.Unix(time.Now().Unix()+sensor.DcIntervalTm, 0).UTC().String()
		}

		ret.List = append(ret.List, &v2.ListSensorReply_Details{
			ID:              sensor.ID,
			IP:              sensor.IP,
			Hostname:        sensor.DCHostName,
			Domain:          sensor.Domain,
			Status:          sensor.Status,
			Version:         sensor.Version,
			NewVersion:      newVer,
			PktStatus:       sensor.PktStatus,
			LogStatus:       sensor.LogStatus,
			SensorTime:      sensorTime,
			Remark:          sensor.Remark,
			PktPluginSwitch: sensor.PktPluginSwitch,

			LogPluginSwitch:    sensor.LogPluginSwitch,
			RpcFwPluginSwitch:  sensor.RpcFwPluginSwitch,
			LdapFwPluginSwitch: sensor.LdapFwPluginSwitch,
			PktPluginStatus:    sensor.PktPluginStatus,
			LogPluginStatus:    sensor.LogPluginStatus,
			RpcFwPluginStatus:  sensor.RpcFwPluginStatus,
			LdapFwPluginStatus: sensor.LdapFwPluginStatus,
			RpcFWCpuUsed:       sensor.RpcFwCpuUsed,
			RpcFWMemUsed:       sensor.RpcFwMemUsed,
			LdapFwCpuUsed:      sensor.LdapFwCpuUsed,
			LdapFwMemUsed:      sensor.LdapFwMemUsed,
			SensorCpuUsed:      sensor.SensorCpuUsed,
			SensorMemUsed:      sensor.SensorMemUsed,

			Platform:     sensor.Platform,
			KernelVer:    sensor.KernelVer,
			MemTotal:     sensor.MemTotal,
			CpuTotal:     sensor.CpuTotal,
			NetIface:     sensor.NetIface,
			BindNetIface: sensor.BindNetIface,
			DcIntervalTm: int32(sensor.DcIntervalTm),
			PerfLimit:    sensor.PerfLimit,
			Events:       events,

			CreateTm:      sensor.CreateTm.String(),
			LastOnlineTm:  sensor.LastOnlineTm.String(),
			LastCollectTm: sensor.LastCollectTm.String(),
		})
	}

	ret.Page = &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: int32(total)}
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}
	return &ret, nil
}

func (s *ADAServiceV2) UpdateSensor(ctx context.Context, in *v2.UpdateSensorReq) (*v2.UpdateSensorReply, error) {
	sensor, err := server.GetSensorByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("get sensor err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取传感器状态失败")
	}

	var cfgPerfLimitOpt = make(map[string]string)
	for _, opt := range []string{"limit_mem_max", "limit_cpu_max"} {
		if val, ok := in.PerfLimit[opt]; ok {
			if sensor.PerfLimit[opt] != val {
				cfgPerfLimitOpt[opt] = val

			} else {
				cfgPerfLimitOpt[opt] = sensor.PerfLimit[opt]
			}
		}
	}

	var switchOpt = make(map[string]string)
	if in.PktPluginSwitch != "" {
		switchOpt["pkt_plugin_switch"] = in.PktPluginSwitch
	}
	if in.LogPluginSwitch != "" {
		switchOpt["log_plugin_switch"] = in.LogPluginSwitch
	}
	if in.RpcFwPluginSwitch != "" {
		switchOpt["rpcfw_plugin_switch"] = in.RpcFwPluginSwitch
	}
	if in.LdapFwPluginSwitch != "" {
		switchOpt["ldapfw_plugin_switch"] = in.LdapFwPluginSwitch
	}

	if len(in.BindNetIface) < 1 {
		logger.Error("empty iface to bind!")
		return nil, status.Errorf(codes.Internal, "网卡不能为空")
	}

	var cfgOpt = make(map[string]string)
	cfgOpt["bind_net_iface"] = strings.Join(in.BindNetIface, ",")
	for k, v := range cfgPerfLimitOpt {
		cfgOpt[k] = v
	}
	for k, v := range switchOpt {
		cfgOpt[k] = v
	}

	err = server.UpdateSensorConf(s.env, in.ID, in.Remark, in.BindNetIface, cfgPerfLimitOpt, switchOpt)
	if err != nil {
		logger.Errorf("update sensor config err:%v", err)
		return nil, status.Errorf(codes.Internal, "更新传感器配置失败")
	}

	err = s.updateSensorCache(ctx, cache.SensorIDKey(in.ID), cfgOpt)
	if err != nil {
		logger.Errorf("update sensor cache err:%v", err)
		return nil, status.Errorf(codes.InvalidArgument, "更新传感器配置失败")
	}

	return &v2.UpdateSensorReply{Result: aCommon.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) CmdSensor(ctx context.Context, in *v2.CmdSensorReq) (*v2.CmdSensorReply, error) {
	// 仅支持: delete | uninstall
	switch in.Cmd {
	case "delete":
		// delete 仅删除服务端配置
		err := server.DeleteSensor(s.env, in.ID)
		if err != nil {
			logger.Errorf("uninstall sensor err:%v", err)
		}

		err = s.env.RedisCli.Del(ctx, cache.SensorIDKey(in.ID)).Err()
		if err != nil {
			logger.Errorf("uninstall sensor err:%v", err)
			return nil, status.Errorf(codes.Internal, "删除sensor失败")
		}
		return &v2.CmdSensorReply{Result: aCommon.RESP_SUCCESS}, nil
	case "uninstall":
		err := server.DeleteSensor(s.env, in.ID)
		if err != nil {
			logger.Errorf("uninstall sensor err:%v", err)
			return nil, status.Errorf(codes.Internal, "卸载sensor失败")
		}

		err = s.env.RedisCli.Del(ctx, cache.SensorIDKey(in.ID)).Err()
		if err != nil {
			logger.Errorf("uninstall sensor err:%v", err)
			return nil, status.Errorf(codes.Internal, "卸载sensor失败")
		}

		var adaMsg sCommon.AdaMessage
		adaMsg.MsgType = sCommon.T_CMD_UNINSTALL_ALL
		adaMsg.TaskID = uuid.NewString()
		adaMsg.Timestamp = time.Now().Unix()
		adaMsg.Version = version.BuildVersion
		adaMsg.AgentID = in.ID
		adaMsg.Data = map[string]string{"plugin": "all"}

		if err := s.pushCmdSensor(ctx, adaMsg, true); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "下发命令(%s)失败:%v", in.Cmd, err)
		}
	default:
		return &v2.CmdSensorReply{Result: aCommon.RESP_FAILED}, nil
	}

	return &v2.CmdSensorReply{Result: aCommon.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) DownloadSensor(ctx context.Context, in *v2.DownloadSensorReq) (*v2.DownloadSensorReply, error) {
	newVer, err := s.getSensorVersion()
	if err != nil {
		logger.Errorf("get latest sensor version err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取传感器失败")
	}

	sensorName := fmt.Sprintf("ada_sensor_installer_%s_%s.exe", in.Type, newVer)
	sensorPath := path.Join(common.DOWNLOAD_PATH, "sensor", newVer, sensorName)
	sensorFile, err := os.Open(sensorPath)
	if err != nil {
		logger.Errorf("sensor not found err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取传感器失败")
	}
	defer sensorFile.Close()

	newPath := path.Join(common.DOWNLOAD_PATH, "sensor", sensorName)
	newFile, err := os.Create(newPath)
	if err != nil {
		logger.Errorf("create file err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取传感器失败")
	}
	defer newFile.Close()

	_, err = io.Copy(newFile, sensorFile)
	if err != nil {
		logger.Errorf("copy file err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取传感器失败")
	}

	return &v2.DownloadSensorReply{Path: sensorName}, nil
}

func (s *ADAServiceV2) UpdateSensorVersion(ctx context.Context, in *v2.UpdateSensorVersionReq) (*v2.UpdateSensorVersionReply, error) {
	ret := &v2.UpdateSensorVersionReply{}
	ret.Result = aCommon.RESP_FAILED

	// 判断版本
	sensor, err := server.GetSensorByID(s.env, in.SensorId)
	if err != nil {
		logger.Errorf("get agent err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取域控传感器状态失败")
	}
	if sensor.Version > in.Version {
		logger.Errorf("version err")
		return nil, status.Errorf(codes.Internal, "版本异常")
	}

	// 判断状态
	if sensor.Status != sCommon.SensorStatusRun {
		return nil, status.Errorf(codes.Internal, "域控传感器未处于运行中")
	}

	newVer, err := s.getSensorVersion()
	if err != nil {
		logger.Errorf("get latest sensor version err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取传感器失败")
	}

	// 根据sensorID 更新的sensor
	var adaMsg sCommon.AdaMessage
	adaMsg.MsgType = sCommon.T_PLUG_BIN_UPDATE
	adaMsg.TaskID = uuid.NewString()
	adaMsg.Timestamp = time.Now().Unix()
	adaMsg.Version = newVer
	adaMsg.AgentID = in.SensorId

	// TODO: 读取sensor .zip文件
	//adaMsg.Data =

	if err := s.pushCmdSensor(ctx, adaMsg, true); err != nil {
		logger.Errorf("redis public err:%v", err)
		return nil, status.Errorf(codes.Internal, "下发更新失败")
	}

	// TODO: sensor 配置是否需要更新？？

	ret.Result = aCommon.RESP_SUCCESS
	return ret, nil
}

func (s *ADAServiceV2) getSensorVersion() (string, error) {
	newVer, err := s.env.RedisCli.Get(context.Background(), sCommon.SensorLatestVersionKey).Result()
	if err != nil {
		logger.Errorf("redis get err:%v", err)
		return "", err
	}

	return newVer, nil
}

func (s *ADAServiceV2) pushCmdSensor(ctx context.Context, cmdMsg sCommon.AdaMessage, sync bool) error {
	cmdStr, err := jsoniter.MarshalToString(cmdMsg)
	if err != nil {
		logger.Errorf("json marshal failed: %v", err)
		return err
	}

	// publish config to agent(redis)
	err = s.env.RedisCli.Publish(ctx, sCommon.SensorCmdChannel, cmdStr).Err()
	if err != nil {
		logger.Errorf("redis public err:%v", err)
		return err
	}

	if !sync {
		return nil
	}

	// 同步等待 下发结果
	taskSucc := false
	taskKey := fmt.Sprintf("%s_%s", sCommon.SensorCmdRespKey, cmdMsg.TaskID)
	for i := 0; i < 40; i++ {
		time.Sleep(1 * time.Second)
		succ := s.env.RedisCli.HGet(ctx, taskKey, "succeed").Val()
		if succ == "" {
			continue
		}
		if succ == "1" {
			// task succeed
			taskSucc = true
			break
		}
	}
	if !taskSucc {
		logger.Errorf("sync task result fialed or timeout, task_id:%s, sensor_id:%s", cmdMsg.TaskID, cmdMsg.AgentID)
		errMsg := s.env.RedisCli.HGet(ctx, taskKey, "msg").Val()
		return fmt.Errorf("sync task err_msg:%s", errMsg)
	}

	return nil
}

func (s *ADAServiceV2) updateSensorCache(ctx context.Context, sensorId string, Info map[string]string) error {
	err := s.env.RedisCli.HMSet(ctx, sensorId, Info).Err()
	if err != nil {
		logger.Errorf("redis public err:%v", err)
		return err
	}

	return nil
}
