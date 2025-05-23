package stats

import (
	sCommon "ada/agent/sensor/common"
	"ada/infra/version"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/shirou/gopsutil/mem"
	logger "github.com/sirupsen/logrus"
)

type State struct {
	ctx          context.Context
	rdxCli       *redis.Client
	sensorId     string
	sensorStatus string
	fqdn         string
}

func New(ctx context.Context, rdxCli *redis.Client, sensorId string) *State {
	fqdn := GetFQDNName()
	return &State{ctx: ctx, rdxCli: rdxCli, sensorId: sensorId, sensorStatus: sCommon.SensorStatusRun, fqdn: fqdn}
}

func (s *State) Serve(wg *sync.WaitGroup, plugProcessMap map[string]uint32) {
	defer wg.Done()

	stateTicker := time.NewTicker(20 * time.Second)
	defer stateTicker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-stateTicker.C:
			{
				msg, err := s.getSensorState(s.ctx, plugProcessMap)
				if err != nil {
					if err == context.Canceled || err == context.DeadlineExceeded {
						logger.Infof("getSensorState cancelled: %v", err)
						return
					}
					logger.Warningf("get sensor state err:%v, continue", err)
					continue
				}

				if err := s.pushSensorState(msg); err != nil {
					logger.Warningf("push sensor state err:%v, continue", err)
					continue
				}
				logger.Debug("push stats to server ok")
			}
		}
	}
}

func (s *State) pushSensorState(msg *sCommon.AdaMessage) error {
	statsByte, err := json.Marshal(msg)
	if err != nil {
		return err
	}

	err = s.rdxCli.LPush(s.ctx, sCommon.SensorStateQueue, statsByte).Err()
	if err != nil {
		return err
	}

	return nil
}

func (s *State) getSensorState(ctx context.Context, plugProcessMap map[string]uint32) (*sCommon.AdaMessage, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	msg := sCommon.AdaMessage{
		AgentID: s.sensorId,
		MsgType: sCommon.T_CONF_STATE,
		Data:    map[string]string{"status": s.sensorStatus},
	}

	msg.TaskID = uuid.New().String()
	msg.Version = version.GetBuildVersion()
	msg.Timestamp = time.Now().Unix()
	cardInfo, err := GetNetDevices(true)
	if err != nil {
		logger.Warningf("get card devices err:%v", err)
		return nil, err
	}
	msg.Data["net_iface"] = cardInfo

	msg.Data["fqdn"] = s.fqdn

	msg.Data["status"] = sCommon.SensorStatusRun
	msg.Data["timestamp"] = fmt.Sprintf("%d", time.Now().Unix())
	msg.Data["mem_total"] = ""
	memary, err := mem.VirtualMemory()
	if err == nil {
		msg.Data["mem_total"] = humanReadableBytes(memary.Total)
	}
	msg.Data["cpu_total"] = fmt.Sprintf("%d", runtime.NumCPU())

	msg.Data["pkt_status"] = sCommon.SensorStatusStop
	msg.Data["log_status"] = sCommon.SensorStatusStop

	msg.Data["rpcfw_status"] = sCommon.SensorStatusStop
	msg.Data["rpcfw_cpu_used"] = "0%"
	msg.Data["rpcfw_mem_used"] = "0%"

	msg.Data["ldapfw_status"] = sCommon.SensorStatusStop
	msg.Data["ldapfw_cpu_used"] = "0%"
	msg.Data["ldapfw_mem_used"] = "0%"

	if val, ok := plugProcessMap[sCommon.PlugPktName]; ok && val > 0 {
		msg.Data["pkt_status"] = sCommon.SensorStatusRun
	}

	if val, ok := plugProcessMap[sCommon.PlugEvtName]; ok && val > 0 {
		msg.Data["log_status"] = sCommon.SensorStatusRun
	}

	sensorCpuUsed, sensorMemUsed, rpcfwCpuUsed, ldapfwCpuUsed, rpcfwMemUsed, ldapfwMemUsed, err := GetSensorResUsed(ctx, plugProcessMap, 3*time.Second)
	if err != nil {
		return nil, err
	}

	if rpcfwMemUsed > 0 {
		msg.Data["rpcfw_status"] = sCommon.SensorStatusRun
		msg.Data["rpcfw_cpu_used"] = fmt.Sprintf("%f%%", rpcfwCpuUsed)
		msg.Data["rpcfw_mem_used"] = fmt.Sprintf("%f%%", rpcfwMemUsed)
	}

	if ldapfwMemUsed > 0 {
		msg.Data["ldapfw_status"] = sCommon.SensorStatusRun
		msg.Data["ldapfw_cpu_used"] = fmt.Sprintf("%f%%", ldapfwCpuUsed)
		msg.Data["ldapfw_mem_used"] = fmt.Sprintf("%f%%", ldapfwMemUsed)
	}

	msg.Data["sensor_cpu_used"] = fmt.Sprintf("%f%%", sensorCpuUsed)
	msg.Data["sensor_mem_used"] = fmt.Sprintf("%f%%", sensorMemUsed)

	return &msg, nil
}

func GetSensorResUsed(ctx context.Context, plugProcessMap map[string]uint32, interval time.Duration) (float64, float64, float64, float64, float64, float64, error) {
	var sensorCpuUsed float64
	var sensorMemUsed float64

	var rpcfwCpuUsed float64
	var ldapfwCpuUsed float64
	var rpcfwMemUsed float64
	var ldapfwMemUsed float64

	select {
	case <-ctx.Done():
		return 0, 0, 0, 0, 0, 0, ctx.Err()
	default:
	}

	rpcfwPid, ok := plugProcessMap[sCommon.PlugRpcFwName]
	if ok && rpcfwPid > 0 {
		cpu, mem, err := getProcessCpuMemPercent(ctx, interval, rpcfwPid)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return 0, 0, 0, 0, 0, 0, err
			}
			logger.Warnf("Error getting rpcfw resource usage (pid: %d): %v", rpcfwPid, err)
		} else {
			sensorCpuUsed += cpu
			sensorMemUsed += mem
			rpcfwCpuUsed += cpu
			rpcfwMemUsed += mem
		}
	}

	ldapfwPid, ok := plugProcessMap[sCommon.PlugLdapFwName]
	if ok && ldapfwPid > 0 {
		select {
		case <-ctx.Done():
			return 0, 0, 0, 0, 0, 0, ctx.Err()
		default:
		}
		cpu, mem, err := getProcessCpuMemPercent(ctx, interval, ldapfwPid)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return 0, 0, 0, 0, 0, 0, err
			}
			logger.Warnf("Error getting ldapfw resource usage (pid: %d): %v", ldapfwPid, err)
		} else {
			sensorCpuUsed += cpu
			sensorMemUsed += mem
			ldapfwCpuUsed += cpu
			ldapfwMemUsed += mem
		}
	}

	sensorPid, ok := plugProcessMap[sCommon.SensorSvcName]
	if ok && sensorPid > 0 {
		select {
		case <-ctx.Done():
			return 0, 0, 0, 0, 0, 0, ctx.Err()
		default:
		}
		cpu, mem, err := getProcessCpuMemPercent(ctx, interval, sensorPid)
		if err != nil {
			if err == context.Canceled || err == context.DeadlineExceeded {
				return 0, 0, 0, 0, 0, 0, err
			}
			logger.Warnf("Error getting sensor resource usage (pid: %d): %v", sensorPid, err)
		} else {
			sensorCpuUsed += cpu
			sensorMemUsed += mem
		}
	}

	return sensorCpuUsed, sensorMemUsed, rpcfwCpuUsed, ldapfwCpuUsed, rpcfwMemUsed, ldapfwMemUsed, nil
}
