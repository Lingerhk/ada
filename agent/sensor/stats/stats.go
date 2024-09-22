package stats

import (
	sCommon "ada/agent/sensor/common"
	"ada/infra/version"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/shirou/gopsutil/mem"
	logger "github.com/sirupsen/logrus"
	"runtime"
	"sync"
	"time"
)

type State struct {
	ctx          context.Context
	rdxCli       *redis.Client
	sensorId     string
	sensorStatus string
}

func New(ctx context.Context, rdxCli *redis.Client, sensorId string) *State {
	return &State{ctx: ctx, rdxCli: rdxCli, sensorId: sensorId, sensorStatus: sCommon.SensorStatusRun}
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
				msg, err := s.getSensorState(plugProcessMap)
				if err != nil {
					logger.Warningf("get sensor state err:%v, continue", err)
					continue
				}

				// push to redis queue
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

func (s *State) getSensorState(plugProcessMap map[string]uint32) (*sCommon.AdaMessage, error) {
	msg := sCommon.AdaMessage{
		AgentID: s.sensorId,
		MsgType: sCommon.T_CONF_STATE,
		Data:    map[string]string{"status": s.sensorStatus},
	}

	msg.TaskID = uuid.New().String()
	msg.Version = version.GetBuildVersion()
	msg.Timestamp = time.Now().Unix()
	cardInfo, err := GetNetDevices()
	if err != nil {
		logger.Warningf("get card devices err:%v", err)
		return nil, err
	}
	msg.Data["net_iface"] = cardInfo
	msg.Data["status"] = sCommon.SensorStatusRun
	msg.Data["timestamp"] = fmt.Sprintf("%d", time.Now().Unix())
	msg.Data["mem_total"] = ""
	memary, err := mem.VirtualMemory()
	if err == nil {
		msg.Data["mem_total"] = fmt.Sprintf("%d", memary.Total)
	}
	msg.Data["cpu_total"] = fmt.Sprintf("%d", runtime.NumCPU())

	msg.Data["pkt_status"] = sCommon.SensorStatusStop
	msg.Data["pkt_cpu_used"] = "0%"
	msg.Data["pkt_mem_used"] = "0%"

	msg.Data["log_status"] = sCommon.SensorStatusStop
	msg.Data["log_cpu_used"] = "0%"
	msg.Data["log_mem_used"] = "0%"

	msg.Data["rpcfw_status"] = sCommon.SensorStatusStop
	msg.Data["rpcfw_cpu_used"] = "0%"
	msg.Data["rpcfw_mem_used"] = "0%"

	msg.Data["ldapfw_status"] = sCommon.SensorStatusStop
	msg.Data["ldapfw_cpu_used"] = "0%"
	msg.Data["ldapfw_mem_used"] = "0%"

	var sensorCpuUsed float64
	var sensorMemUsed float32

	ntapPid := plugProcessMap[sCommon.PlugNtapName]
	if ntapPid > 0 {
		cpu, mem, err := getProcessCpuMemPercent(3*time.Second, ntapPid)
		if err == nil {
			msg.Data["pkt_status"] = sCommon.SensorStatusRun
			msg.Data["pkt_cpu_used"] = fmt.Sprintf("%f%%", cpu)
			msg.Data["pkt_mem_used"] = fmt.Sprintf("%f%%", mem)
			sensorCpuUsed += cpu
			sensorMemUsed += mem
		}
	}

	nxlogPid := plugProcessMap[sCommon.PlugNxlogName]
	if nxlogPid > 0 {
		cpu, mem, err := getProcessCpuMemPercent(3*time.Second, nxlogPid)
		if err == nil {
			msg.Data["log_status"] = sCommon.SensorStatusRun
			msg.Data["log_cpu_used"] = fmt.Sprintf("%f%%", cpu)
			msg.Data["log_mem_used"] = fmt.Sprintf("%f%%", mem)
			sensorCpuUsed += cpu
			sensorMemUsed += mem
		}
	}

	rpcfwPid := plugProcessMap[sCommon.PlugRpcFwName]
	if rpcfwPid > 0 {
		cpu, mem, err := getProcessCpuMemPercent(3*time.Second, rpcfwPid)
		if err == nil {
			msg.Data["rpcfw_status"] = sCommon.SensorStatusRun
			msg.Data["rpcfw_cpu_used"] = fmt.Sprintf("%f%%", cpu)
			msg.Data["rpcfw_mem_used"] = fmt.Sprintf("%f%%", mem)
			sensorCpuUsed += cpu
			sensorMemUsed += mem
		}
	}

	ldapfwPid := plugProcessMap[sCommon.PlugLdapFwName]
	if ldapfwPid > 0 {
		cpu, mem, err := getProcessCpuMemPercent(3*time.Second, ldapfwPid)
		if err == nil {
			msg.Data["ldapfw_status"] = sCommon.SensorStatusRun
			msg.Data["ldapfw_cpu_used"] = fmt.Sprintf("%f%%", cpu)
			msg.Data["ldapfw_mem_used"] = fmt.Sprintf("%f%%", mem)
			sensorCpuUsed += cpu
			sensorMemUsed += mem
		}
	}

	sensorPid := plugProcessMap["self"]
	if sensorPid > 0 {
		cpu, mem, err := getProcessCpuMemPercent(3*time.Second, sensorPid)
		if err == nil {
			sensorCpuUsed += cpu
			sensorMemUsed += mem
		}
	}

	// no used currently
	msg.Data["sensor_cpu_used"] = fmt.Sprintf("%f%%", sensorCpuUsed)
	msg.Data["sensor_mem_used"] = fmt.Sprintf("%f%%", sensorMemUsed)

	return &msg, nil
}
