package plugin

import (
	"ada/agent/sensor/common"
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-cmd/cmd"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Plugin struct {
	ctx                context.Context
	rdxCli             *redis.Client
	sensorId           string
	adaHost            string
	pktPluginSwitch    bool
	logPluginSwitch    bool
	rpcFwPluginSwitch  bool
	ldapFwPluginSwitch bool
	ntapBindIface      []string
	cpuMaxLimit        float32
	memMaxLimit        float32

	ntapProc       *cmd.Cmd // ntap process
	PlugProcessMap map[string]uint32
}

func New(ctx context.Context, rdxCli *redis.Client, sensorId, regHost string) *Plugin {
	plug := Plugin{ctx: ctx, rdxCli: rdxCli, sensorId: sensorId, adaHost: regHost}
	plug.ntapBindIface = []string{"0"}
	plug.cpuMaxLimit = float32(0.05)
	plug.memMaxLimit = float32(0.05)

	plugProcessMap := make(map[string]uint32)
	plugProcessMap[common.PlugNtapName] = 0
	plugProcessMap[common.PlugNxlogName] = 0
	plugProcessMap[common.PlugRpcFwName] = 0
	plugProcessMap[common.PlugLdapFwName] = 0
	plug.PlugProcessMap = plugProcessMap

	return &plug
}

func (p *Plugin) Event(wg *sync.WaitGroup) {
	defer wg.Done()

	plugTicker := time.NewTicker(time.Minute)
	defer plugTicker.Stop()

	pubsub := p.rdxCli.PSubscribe(p.ctx, common.SensorCmdChannel)
	defer pubsub.Close()

	for {
		select {
		case <-p.ctx.Done():
			return
		case <-plugTicker.C:
			{
				msg, err := pubsub.ReceiveTimeout(p.ctx, 3*time.Second)
				if err != nil {
					if err := pubsub.Ping(p.ctx); err != nil {
						logger.Errorf("PubSub failure:%s", err.Error())
					}
					continue
				}
				switch msg := msg.(type) {
				case *redis.Message:
					logger.Infof("channel: %s received:%s, ", msg.Channel, msg.Payload)
					go p.cmdSync(msg.Payload) // 并发执行，防止卡住导致stop等指令无法执行
				}
			}
		}
	}
}

func (p *Plugin) cmdSync(msgCmd string) {
	var err error

	var msg common.AdaMessage
	err = json.Unmarshal([]byte(msgCmd), &msg)
	if err != nil {
		logger.Errorf("json unmarshal err:%v", err)
		return
	}

	if msg.AgentID != p.sensorId {
		logger.Debugf("ignore invalid cmd message by sensor_id:%s,this sensor_id:%s", msg.AgentID, p.sensorId)
		return
	}

	logger.Infof("received cmd(task_id:%s) from server: code:%d, msg_type:%d, data:%v", msg.TaskID, msg.Code, msg.MsgType, msg.Data)

	switch msg.MsgType {
	case common.T_CONF_UPDATE:
		err = p.sensorConfUpdate(msg.Data)
	case common.T_PLUG_CONF_UPDATE:
		err = p.pluginConfUpdate(msg.Data)
	case common.T_PLUG_BIN_UPDATE:
		err = p.pluginBinUpdate(msg.Data)
	case common.T_PLUG_BLOCK_UPDATE:
		err = p.blockPolicyUpdate(msg.Data)
	default:
		logger.Warnf("invalid msg_type:%d, ignore", msg.MsgType)
	}
	if err != nil {
		logger.Errorf("execture cmd(msg_type:%d) err:%v", msg.MsgType, err)
		p.cmdResp(msg.TaskID, msg.AgentID, err.Error())
		return
	}

	// 发送cmd resp消息
	p.cmdResp(msg.TaskID, msg.AgentID, "")
}

func (p *Plugin) cmdResp(taskId, sensorId, msg string) {
	// redis 指定的key中写入结果
	result := map[string]string{"succeed": "1", "sensor_id": sensorId, "msg": msg, "timestamp": strconv.FormatInt(time.Now().Unix(), 10)}
	if msg != "" {
		result["succeed"] = "0"
	}

	taskKey := fmt.Sprintf("%s_%s", common.SensorCmdRespKey, taskId)
	_ = p.rdxCli.HMSet(p.ctx, taskKey, result).Err()
	_ = p.rdxCli.Expire(p.ctx, taskKey, 3600*time.Second).Err()
}

func (p *Plugin) Serve(wg *sync.WaitGroup) {
	defer wg.Done()

	plugRunTicker := time.NewTicker(5 * time.Second)
	defer plugRunTicker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			p.stopAllPlugin()
			return
		case <-plugRunTicker.C:
			{
				// 执行插件配置加载
				p.loadConfigure()

				// 执行插件启动
				p.runPlugin()
			}
		}
	}

}

func (p *Plugin) loadConfigure() {
	sensorIDKey := fmt.Sprintf("%s:%s", common.SensorIDPrefixKey, p.sensorId)
	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "pkt_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get pkt switch err:%v", err)
	} else {
		p.pktPluginSwitch = false
		if v == "true" {
			p.pktPluginSwitch = true
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "bind_net_iface").Result()
	if err != nil {
		logger.Errorf("get bind iface err:%v", err)
	} else {
		if v != "" {
			p.ntapBindIface = strings.Split(v, ",")
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "log_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get log switch err:%v", err)
	} else {
		p.logPluginSwitch = false

		if v == "true" {
			p.logPluginSwitch = true
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "rpcfw_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get rpcfw switch err:%v", err)
	} else {
		p.rpcFwPluginSwitch = false
		if v == "true" {
			p.rpcFwPluginSwitch = true
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "ldapfw_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get ldapfw switch err:%v", err)
	} else {
		p.ldapFwPluginSwitch = false
		if v == "true" {
			p.ldapFwPluginSwitch = true
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "limit_cpu_max").Result()
	if err != nil {
		logger.Errorf("get cpu limit err:%v", err)
	} else {
		value, err := strconv.ParseFloat(v, 32)
		if err != nil {
			logger.Errorf("get cpu limit err:%v", err)
		} else {
			p.cpuMaxLimit = float32(value)
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "limit_mem_max").Result()
	if err != nil {
		logger.Errorf("get mem limit err:%v", err)
	} else {
		value, err := strconv.ParseFloat(v, 32)
		if err != nil {
			logger.Errorf("get mem limit err:%v", err)
		} else {
			p.memMaxLimit = float32(value)
		}
	}

	logger.Debugf("load sensor configure: pkt_switch:%t, log_switch:%t, rpcfw_switch:%t, ldapfw_switch:%t, bind_iface:%v, cpu_limit:%f, mem_limit:%f", p.pktPluginSwitch, p.logPluginSwitch, p.rpcFwPluginSwitch, p.ldapFwPluginSwitch, p.ntapBindIface, p.cpuMaxLimit, p.memMaxLimit)
}

func (p *Plugin) runPlugin() {
	var err error

	plugs, err := p.getPluginStatus()
	if err != nil {
		logger.Errorf("get plugin svc status err:%v", err)
		return
	}

	if p.logPluginSwitch {
		// 如果没有启动，则start
		if !plugs[common.PlugNxlogName] {
			if err = startNxlogPlugin(false); err != nil {
				logger.Infof("try to start nxlog svc err:%v", err)
			}
		}
	} else {
		// 如果已启动，则stop
		if err = stopNxlogPlugin(); err != nil {
			logger.Infof("try to stop nxlog svc err:%v", err)
		}
	}

	if p.rpcFwPluginSwitch {
		// 如果没有启动，则start
		if !plugs[common.PlugRpcFwName] {
			if err = startRpcFwPlugin(false); err != nil {
				logger.Infof("try to start rpcfw svc err:%v", err)
			}
		}
	} else {
		// 如果已启动，则stop
		if err = stopRpcFwPlugin(); err != nil {
			logger.Infof("try to stop rpcfw svc err:%v", err)
		}
	}

	if p.ldapFwPluginSwitch {
		// 如果没有启动，则start
		if !plugs[common.PlugLdapFwName] {
			if err = startLdapFwPlugin(false); err != nil {
				logger.Infof("try to start ldapfw svc err:%v", err)
			}
		}
	} else {
		// 如果已启动，则stop
		if err = stopLdapFwPlugin(); err != nil {
			logger.Infof("try to stop ldapfw svc err:%v", err)
		}
	}
}

func (p *Plugin) stopAllPlugin() {
	p.ntapProc.Stop() // stop ntap
	stopNxlogPlugin()
	stopRpcFwPlugin()
	stopLdapFwPlugin()
}

func (p *Plugin) RunNtap(wg *sync.WaitGroup) {
	defer wg.Done()

	plugNtapTicker := time.NewTicker(3 * time.Second)
	defer plugNtapTicker.Stop()

	var origBindIface = p.ntapBindIface[0]

	ntapBin := filepath.Join(common.SensorDir, "ntap", common.PlugNtapProcName)

	p.ntapProc = cmd.NewCmd(ntapBin)
	p.ntapProc.Dir = common.GetCurrentPath()
	p.ntapProc.Args = getNtapArgs(p.adaHost, origBindIface)

	// TODO: fix 不行  如果启动前还有ntap进行（僵尸进程），则killed
	TryKillProcess(common.PlugNtapProcName)

	var stop bool
	go func() {
		for {
			if stop {
				return
			}
			time.Sleep(2 * time.Second)

			currProcPid := p.PlugProcessMap[common.PlugNtapName]

			// check if need stop this plugin by switch
			if p.pktPluginSwitch == false && currProcPid != 0 {
				logger.Infof("will stop ntap(%d) process by switch", currProcPid)
				p.ntapProc.Stop()
				p.PlugProcessMap[common.PlugNtapName] = 0
				continue
			}

			// check if need stop this plugin by bind port changed
			if currProcPid != 0 && p.ntapBindIface[0] != origBindIface {
				logger.Infof("will stop ntap(%d) process by bind changed(iface_id %s to %s)", currProcPid, origBindIface, p.ntapBindIface[0])
				p.ntapProc.Stop()
				p.PlugProcessMap[common.PlugNtapName] = 0
				continue
			}
		}
	}()

	for {
		select {
		case <-p.ctx.Done():
			p.ntapProc.Stop()
			stop = true
			return
		case <-plugNtapTicker.C:
			{
				if !p.pktPluginSwitch {
					time.Sleep(2 * time.Second)
					continue
				} else {
					// 执行到这里意味着,ntap程序已经退出了. 如果switch是开的话，需要重新拉起
					p.ntapProc = cmd.NewCmd(ntapBin)
					p.ntapProc.Dir = common.GetCurrentPath()
					p.ntapProc.Args = getNtapArgs(p.adaHost, p.ntapBindIface[0])
					origBindIface = p.ntapBindIface[0]
				}

				statusChan := p.ntapProc.Start()
				time.Sleep(300 * time.Millisecond)

				logger.Infof("started ntap process with pid %d", p.ntapProc.Status().PID)
				p.PlugProcessMap[common.PlugNtapName] = uint32(p.ntapProc.Status().PID)

				done := <-statusChan
				p.PlugProcessMap[common.PlugNtapName] = 0

				var stopDesc = "signal"
				if done.Complete {
					stopDesc = "kill"
				}
				logger.Infof("ntap stopped(history_pid:%d) by %s, exit_code:%d", done.PID, stopDesc, done.Exit)
			}
		}
	}
}

func getNtapArgs(adaHost, bindIface string) []string {
	bpf := fmt.Sprintf("(tcp) and (not (host %s and port 9091))", adaHost)
	return []string{"/c", "-K", "-i", bindIface, "-c", fmt.Sprintf("%s:9093", adaHost), "-f", bpf}
}
