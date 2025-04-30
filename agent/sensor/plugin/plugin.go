package plugin

import (
	"ada/agent/sensor/common"
	"ada/agent/sensor/config"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
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
	cpuMaxLimit        float32
	memMaxLimit        float32

	plugEvtThread        *evtPlugin
	plugPktThread        *pktPlugin
	PlugProcessMap       map[string]uint32
	PlugConfigChangedMap map[string]bool // 记录插件配置是否发生变化
}

func New(ctx context.Context, rdxCli *redis.Client, sensorId string, sensorCfg config.SensorCfg) (*Plugin, error) {
	var err error

	plug := Plugin{ctx: ctx, rdxCli: rdxCli, sensorId: sensorId, adaHost: sensorCfg.RegHost}
	plug.cpuMaxLimit = float32(0.15)
	plug.memMaxLimit = float32(0.15)

	plugProcessMap := make(map[string]uint32)
	plugProcessMap[common.SensorSvcName] = 0
	plugProcessMap[common.PlugPktName] = 0
	plugProcessMap[common.PlugEvtName] = 0
	plugProcessMap[common.PlugRpcFwName] = 0
	plugProcessMap[common.PlugLdapFwName] = 0
	plug.PlugProcessMap = plugProcessMap

	plugConfigChangedMap := make(map[string]bool)
	plugConfigChangedMap[common.PlugEvtName] = false
	plugConfigChangedMap[common.PlugPktName] = false
	plugConfigChangedMap[common.PlugRpcFwName] = false
	plugConfigChangedMap[common.PlugLdapFwName] = false
	plug.PlugConfigChangedMap = plugConfigChangedMap

	plug.plugEvtThread, err = NewEvtPlugin(sensorCfg.RegHost, sensorCfg.EvtSrvPort)
	if err != nil {
		logger.Errorf("new evt plugin err:%v", err)
		return nil, err
	}
	plug.plugPktThread, err = NewPktPlugin(ctx, sensorCfg.RegHost, sensorCfg.PktSrvPort)
	if err != nil {
		logger.Errorf("new pkt plugin err:%v", err)
		return nil, err
	}

	return &plug, nil
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

	p.loadConfigure()

	for {
		select {
		case <-p.ctx.Done():
			logger.Info("received sensor stop signal, stop all plugin!")
			p.stopAllPlugin()
			return
		case <-time.After(5 * time.Second):
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
	for pluginName, _ := range p.PlugConfigChangedMap {
		p.PlugConfigChangedMap[pluginName] = false
	}

	sensorIDKey := fmt.Sprintf("%s:%s", common.SensorIDPrefixKey, p.sensorId)

	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "pkt_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get pkt switch err:%v", err)
	} else if v != "" {
		pktPluginSwitch, err := strconv.ParseBool(v)
		if err == nil {
			if v != strconv.FormatBool(p.pktPluginSwitch) {
				logger.Infof("pkt plugin switch changed to %s", v)
				p.PlugConfigChangedMap[common.PlugPktName] = true
			}

			p.pktPluginSwitch = pktPluginSwitch
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "bind_net_iface").Result()
	if err != nil {
		logger.Errorf("get bind iface err:%v", err)
	} else if v != "" {
		// v 格式为网卡索引："eth0,eth1". 多个网卡用逗号分隔, 转位 int 数组
		pktBindIfaceNames := strings.Split(v, ",")
		if len(pktBindIfaceNames) > 0 {
			// check if all iface indexes are changed: compare []int
			if !reflect.DeepEqual(p.plugPktThread.IfaceNames, pktBindIfaceNames) {
				logger.Infof("pkt bind iface names changed to %v", pktBindIfaceNames)
				p.PlugConfigChangedMap[common.PlugPktName] = true
			}

			p.plugPktThread.IfaceNames = pktBindIfaceNames
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "pkt_bpf_filter").Result()
	if err != nil && err != redis.Nil {
		logger.Errorf("get bpf filter err:%v", err)
	} else if err == redis.Nil {
		logger.Debug("pkt bpf filter not set")
	} else if v != "" {
		err = p.plugPktThread.SetBpfFilter(v)
		if err != nil {
			logger.Errorf("set bpf filter err:%v", err)
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "log_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get log switch err:%v", err)
	} else if v != "" {
		logPluginSwitch, err := strconv.ParseBool(v)
		if err == nil {
			if v != strconv.FormatBool(p.logPluginSwitch) {
				logger.Infof("log plugin switch changed to %s", v)
			}

			p.logPluginSwitch = logPluginSwitch
		}
	}

	// 获取evt plugin 的配置
	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "log_evt_filter").Result()
	if err != nil && err != redis.Nil {
		logger.Errorf("get log event filter err:%v", err)
	} else if err == redis.Nil {
		logger.Debug("log event filter not set")
	} else if v != "" {
		// check event filter format: json {"ignores":[{"EventID":[1,2,3]}],"includes":[{"Level":[2,3]}]}
		var eventFilter map[string]interface{}
		err = json.Unmarshal([]byte(v), &eventFilter)
		if err != nil {
			logger.Errorf("unmarshal event filter err:%v", err)
		} else {
			if p.plugEvtThread.EventFilter != v {
				logger.Infof("log event filter changed to %v", v)
				p.PlugConfigChangedMap[common.PlugEvtName] = true
				p.plugEvtThread.EventFilter = v
			}
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "rpcfw_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get rpcfw switch err:%v", err)
	} else if v != "" {
		rpcFwPluginSwitch, err := strconv.ParseBool(v)
		if err == nil {
			if v != strconv.FormatBool(p.rpcFwPluginSwitch) {
				logger.Infof("rpcfw plugin switch changed to %s", v)
			}

			p.rpcFwPluginSwitch = rpcFwPluginSwitch
		}
	}

	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "ldapfw_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get ldapfw switch err:%v", err)
	} else if v != "" {
		ldapFwPluginSwitch, err := strconv.ParseBool(v)
		if err == nil {
			if v != strconv.FormatBool(p.ldapFwPluginSwitch) {
				logger.Infof("ldapfw plugin switch changed to %s", v)
			}

			p.ldapFwPluginSwitch = ldapFwPluginSwitch
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
}

func (p *Plugin) runPlugin() {
	var err error

	plugs, err := p.getPluginStatus()
	if err != nil {
		logger.Errorf("get plugin svc status err:%v", err)
		return
	}

	if p.logPluginSwitch {
		// if plugin is installed and not running, start it
		if !p.plugEvtThread.IsRunning() {
			logger.Info("evt plugin is not running, start it")
			if err = p.plugEvtThread.Start(); err != nil {
				logger.Infof("start evt plugin err:%v", err)
			}
		}

		if p.PlugConfigChangedMap[common.PlugEvtName] { // only log_eid_filter changed, need reload
			logger.Info("evt plugin config changed, reload it")
			// if plugin is installed and running, reload it
			if err = p.plugEvtThread.Reload(); err != nil {
				logger.Infof("reload evt plugin err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugEvtName] = 1

	} else {
		// if plugin is installed and running, stop it
		if p.plugEvtThread.IsRunning() {
			if err = p.plugEvtThread.Stop(); err != nil {
				logger.Infof("stop evt plugin err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugEvtName] = 0
	}

	if p.pktPluginSwitch {
		// if plugin is installed and not running, start it
		if !p.plugPktThread.IsRunning() {
			if err = p.plugPktThread.Start(); err != nil {
				logger.Infof("start pkt plugin err:%v", err)
			}
		}

		if p.PlugConfigChangedMap[common.PlugPktName] {
			// if plugin is installed and running, reload it
			logger.Info("reload pkt plugin by config changed")
			if err = p.plugPktThread.Reload(); err != nil {
				logger.Infof("reload pkt plugin err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugPktName] = 1
	} else {
		// if plugin is installed and running, stop it
		if p.plugPktThread.IsRunning() {
			if err = p.plugPktThread.Stop(); err != nil {
				logger.Infof("stop pkt plugin err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugPktName] = 0
	}

	if p.rpcFwPluginSwitch {
		// if plugin is installed and not running, start it
		if isRunning, ok := plugs[common.PlugRpcFwName]; ok && !isRunning {
			if err = startRpcFwPlugin(false); err != nil {
				logger.Infof("try to start rpcfw svc err:%v", err)
			}
		}
		if p.PlugConfigChangedMap[common.PlugRpcFwName] {
			// if plugin's config changed, reload it
			logger.Info("reload rpcfw plugin by config changed")
			if err = reloadRpcFwPlugin(); err != nil {
				logger.Infof("reload rpcfw plugin err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugRpcFwName] = 1
	} else {
		// is installed and running, stop it
		if isRunning, ok := plugs[common.PlugRpcFwName]; ok && isRunning {
			if err = stopRpcFwPlugin(); err != nil {
				logger.Infof("try to stop rpcfw svc err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugRpcFwName] = 0
	}

	if p.ldapFwPluginSwitch {
		// is installed and not running, start it
		if isRunning, ok := plugs[common.PlugLdapFwName]; ok && !isRunning {
			if err = startLdapFwPlugin(false); err != nil {
				logger.Infof("try to start ldapfw svc err:%v", err)
			}
		}

		if p.PlugConfigChangedMap[common.PlugLdapFwName] {
			// if plugin's config changed, reload it
			logger.Info("reload ldapfw plugin by config changed")
			if err = reloadLdapFwPlugin(); err != nil {
				logger.Infof("reload ldapfw plugin err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugLdapFwName] = 1
	} else {
		// is installed and running, stop it
		if isRunning, ok := plugs[common.PlugLdapFwName]; ok && isRunning {
			if err = stopLdapFwPlugin(); err != nil {
				logger.Infof("try to stop ldapfw svc err:%v", err)
			}
		}

		p.PlugProcessMap[common.PlugLdapFwName] = 0
	}
}

func (p *Plugin) stopAllPlugin() {
	if isLdapFwInstalled() {
		stopLdapFwPlugin()
	}

	if isRpcFwInstalled() {
		stopRpcFwPlugin()
	}

	if p.plugPktThread.IsRunning() {
		p.plugPktThread.Stop()
	}

	if p.plugEvtThread.IsRunning() {
		p.plugEvtThread.Stop()
	}
}
