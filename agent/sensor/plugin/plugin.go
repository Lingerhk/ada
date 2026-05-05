package plugin

import (
	"ada/agent/sensor/common"
	"ada/agent/sensor/config"
	"ada/agent/sensor/stats"
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
	tsharkPluginSwitch bool
	rpcFwPluginSwitch  bool
	ldapFwPluginSwitch bool
	cpuMaxLimit        float64
	memMaxLimit        float64

	plugEvtThread         *evtPlugin
	plugPktThread         *pktPlugin
	plugTsharkThread      *tsharkPlugin
	mu                    sync.RWMutex      // Protects all maps below
	PlugProcessMap        map[string]uint32 // Process ID map
	PlugConfigChangedMap  map[string]bool   // 记录插件配置是否发生变化
	plugProcessAutoResMap map[string]bool   // Track plugins stopped by AutoResLimit
}

func New(ctx context.Context, rdxCli *redis.Client, sensorId string, sensorCfg config.SensorCfg) (*Plugin, error) {
	var err error

	plug := Plugin{ctx: ctx, rdxCli: rdxCli, sensorId: sensorId, adaHost: sensorCfg.RegHost}
	plug.cpuMaxLimit = float64(0.15 * 100) // 15%
	plug.memMaxLimit = float64(0.15 * 100) // 15%

	plugProcessMap := make(map[string]uint32)
	plugProcessMap[common.SensorSvcName] = 0
	plugProcessMap[common.PlugPktName] = 0
	plugProcessMap[common.PlugEvtName] = 0
	plugProcessMap[common.PlugTsharkName] = 0
	plugProcessMap[common.PlugRpcFwName] = 0
	plugProcessMap[common.PlugLdapFwName] = 0
	plug.PlugProcessMap = plugProcessMap

	plugConfigChangedMap := make(map[string]bool)
	plugConfigChangedMap[common.PlugEvtName] = false
	plugConfigChangedMap[common.PlugPktName] = false
	plugConfigChangedMap[common.PlugTsharkName] = false
	plugConfigChangedMap[common.PlugRpcFwName] = false
	plugConfigChangedMap[common.PlugLdapFwName] = false
	plug.PlugConfigChangedMap = plugConfigChangedMap

	plugProcessAutoResMap := make(map[string]bool)
	plugProcessAutoResMap[common.PlugPktName] = false
	plugProcessAutoResMap[common.PlugEvtName] = false
	plugProcessAutoResMap[common.PlugTsharkName] = false
	plugProcessAutoResMap[common.PlugRpcFwName] = false
	plugProcessAutoResMap[common.PlugLdapFwName] = false
	plug.plugProcessAutoResMap = plugProcessAutoResMap

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
	plug.plugTsharkThread, err = NewTsharkPlugin(ctx, sensorCfg.RegHost, sensorCfg.EvtSrvPort)
	if err != nil {
		logger.Errorf("new tshark plugin err:%v", err)
		return nil, err
	}

	return &plug, nil
}

func (p *Plugin) Event(wg *sync.WaitGroup) {
	defer wg.Done()

	// NOTE:
	// Previously this code only polled PubSub once per minute, which can easily cause
	// Portal-triggered operations (that wait ~40s) to time out.
	// Consume the channel continuously.

	// Use PSUBSCRIBE because Redis ACL user `ada_sensor` is granted +psubscribe (not +subscribe).
	pubsub := p.rdxCli.PSubscribe(p.ctx, common.SensorCmdChannel)
	defer pubsub.Close()

	ch := pubsub.Channel(redis.WithChannelSize(256))
	for {
		select {
		case <-p.ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				// connection closed; try a light ping for logging then exit
				if err := pubsub.Ping(p.ctx); err != nil {
					logger.Errorf("PubSub closed/ping failed: %s", err.Error())
				}
				return
			}
			logger.Infof("channel: %s received:%s", msg.Channel, msg.Payload)
			go p.cmdSync(msg.Payload) // 并发执行，防止卡住导致stop等指令无法执行
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
	case common.T_CMD_UNINSTALL_ALL:
		// uninstall sensor: we using WinRM to execute uninstall-adaegis.ps1 from server side.
		logger.Info("received uninstall sensor cmd, will execute uninstall-adaegis.ps1 from server side")
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
	// NOTE: Do NOT reset PlugConfigChangedMap here!
	// Flags should only be reset after successful reload in runPlugin()

	sensorIDKey := fmt.Sprintf("%s:%s", common.SensorIDPrefixKey, p.sensorId)

	p.mu.RLock()
	pktAutoRes := p.plugProcessAutoResMap[common.PlugPktName]
	evtAutoRes := p.plugProcessAutoResMap[common.PlugEvtName]
	tsharkAutoRes := p.plugProcessAutoResMap[common.PlugTsharkName]
	rpcFwAutoRes := p.plugProcessAutoResMap[common.PlugRpcFwName]
	ldapFwAutoRes := p.plugProcessAutoResMap[common.PlugLdapFwName]
	p.mu.RUnlock()

	if pktAutoRes {
		logger.Infof("pkt plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigurePktPlugin(sensorIDKey)
	}

	if evtAutoRes {
		logger.Infof("evt plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigureEvtPlugin(sensorIDKey)
	}

	if tsharkAutoRes {
		logger.Infof("tshark plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigureTsharkPlugin(sensorIDKey)
	}

	if rpcFwAutoRes {
		logger.Infof("rpcfw plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigureRpcFwPlugin(sensorIDKey)
	}

	if ldapFwAutoRes {
		logger.Infof("ldapfw plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigureLdapFwPlugin(sensorIDKey)
	}

	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "limit_cpu_max").Result()
	if err != nil {
		logger.Errorf("get cpu limit err:%v", err)
	} else {
		value, err := strconv.ParseFloat(v, 32)
		if err != nil {
			logger.Errorf("get cpu limit err:%v", err)
		} else {
			p.cpuMaxLimit = float64(value * 100)
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
			p.memMaxLimit = float64(value * 100)
		}
	}
}

func (p *Plugin) loadConfigurePktPlugin(sensorIDKey string) {
	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "pkt_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get pkt switch err:%v", err)
	} else if v != "" {
		pktPluginSwitch, err := strconv.ParseBool(v)
		if err == nil {
			if v != strconv.FormatBool(p.pktPluginSwitch) {
				logger.Infof("pkt plugin switch changed to %s", v)
				p.mu.Lock()
				p.PlugConfigChangedMap[common.PlugPktName] = true
				p.mu.Unlock()
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
			currentIfaceNames := p.plugPktThread.GetIfaceNames()
			if !reflect.DeepEqual(currentIfaceNames, pktBindIfaceNames) {
				logger.Infof("pkt bind iface names changed to %v", pktBindIfaceNames)
				p.mu.Lock()
				p.PlugConfigChangedMap[common.PlugPktName] = true
				p.mu.Unlock()
			}
			p.plugPktThread.SetIfaceNames(pktBindIfaceNames)
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
}

func (p *Plugin) loadConfigureEvtPlugin(sensorIDKey string) {
	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "log_plugin_switch").Result()
	if err != nil {
		logger.Errorf("get log switch err:%v", err)
	} else if v != "" {
		logPluginSwitch, err := strconv.ParseBool(v)
		if err == nil {
			if v != strconv.FormatBool(p.logPluginSwitch) {
				logger.Infof("log plugin switch changed to %s", v)
				// FIX: Add missing config change flag for switch change
				p.mu.Lock()
				p.PlugConfigChangedMap[common.PlugEvtName] = true
				p.mu.Unlock()
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
		var eventFilter map[string]any
		err = json.Unmarshal([]byte(v), &eventFilter)
		if err != nil {
			logger.Errorf("unmarshal event filter err:%v", err)
		} else {
			currentFilter := p.plugEvtThread.GetEventFilter()
			if currentFilter != v {
				logger.Infof("log event filter changed to %v", v)
				p.mu.Lock()
				p.PlugConfigChangedMap[common.PlugEvtName] = true
				p.mu.Unlock()
				p.plugEvtThread.SetEventFilter(v)
			}
		}
	}
}

func (p *Plugin) loadConfigureTsharkPlugin(sensorIDKey string) {
	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "tshark_plugin_switch").Result()
	if err != nil && err != redis.Nil {
		logger.Errorf("get tshark switch err:%v", err)
	} else if v != "" {
		tsharkPluginSwitch, err := strconv.ParseBool(v)
		if err == nil {
			if v != strconv.FormatBool(p.tsharkPluginSwitch) {
				logger.Infof("tshark plugin switch changed to %s", v)
				p.mu.Lock()
				p.PlugConfigChangedMap[common.PlugTsharkName] = true
				p.mu.Unlock()
			}
			p.tsharkPluginSwitch = tsharkPluginSwitch
		}
	}

	var ifaceNames []string
	v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "tshark_bind_net_iface").Result()
	if err != nil && err != redis.Nil {
		logger.Errorf("get tshark bind iface err:%v", err)
	}
	if v == "" {
		v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "bind_net_iface").Result()
		if err != nil && err != redis.Nil {
			logger.Errorf("get bind iface for tshark err:%v", err)
		}
	}
	if v != "" {
		ifaceNames = strings.Split(v, ",")
		currentIfaceNames := p.plugTsharkThread.GetIfaceNames()
		if !reflect.DeepEqual(currentIfaceNames, ifaceNames) {
			logger.Infof("tshark bind iface names changed to %v", ifaceNames)
			p.mu.Lock()
			p.PlugConfigChangedMap[common.PlugTsharkName] = true
			p.mu.Unlock()
			p.plugTsharkThread.SetIfaceNames(ifaceNames)
		}
	}

	var tsharkPath, captureFilter, displayFilter, fields string
	if v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "tshark_path").Result(); err == nil {
		tsharkPath = v
	} else if err != redis.Nil {
		logger.Errorf("get tshark path err:%v", err)
	}
	if v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "tshark_capture_filter").Result(); err == nil {
		captureFilter = v
	} else if err != redis.Nil {
		logger.Errorf("get tshark capture filter err:%v", err)
	}
	if v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "tshark_display_filter").Result(); err == nil {
		displayFilter = v
	} else if err != redis.Nil {
		logger.Errorf("get tshark display filter err:%v", err)
	}
	if v, err = p.rdxCli.HGet(p.ctx, sensorIDKey, "tshark_fields").Result(); err == nil {
		fields = v
	} else if err != redis.Nil {
		logger.Errorf("get tshark fields err:%v", err)
	}

	if p.plugTsharkThread.SetConfig(tsharkPath, captureFilter, displayFilter, fields) {
		p.mu.Lock()
		p.PlugConfigChangedMap[common.PlugTsharkName] = true
		p.mu.Unlock()
	}
}

func (p *Plugin) loadConfigureRpcFwPlugin(sensorIDKey string) {
	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "rpcfw_plugin_switch").Result()
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
}

func (p *Plugin) loadConfigureLdapFwPlugin(sensorIDKey string) {
	v, err := p.rdxCli.HGet(p.ctx, sensorIDKey, "ldapfw_plugin_switch").Result()
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
}

func (p *Plugin) runPlugin() {
	var err error

	// check plugin process status
	statusMap, err := p.getPluginStatus()
	if err != nil {
		logger.Errorf("get plugin status err:%v", err)
		// don't return here, maybe only part of service can't access
	}

	// Read config change flags with lock
	p.mu.RLock()
	evtAutoRes := p.plugProcessAutoResMap[common.PlugEvtName]
	pktAutoRes := p.plugProcessAutoResMap[common.PlugPktName]
	tsharkAutoRes := p.plugProcessAutoResMap[common.PlugTsharkName]
	rpcFwAutoRes := p.plugProcessAutoResMap[common.PlugRpcFwName]
	ldapFwAutoRes := p.plugProcessAutoResMap[common.PlugLdapFwName]
	evtConfigChanged := p.PlugConfigChangedMap[common.PlugEvtName]
	pktConfigChanged := p.PlugConfigChangedMap[common.PlugPktName]
	tsharkConfigChanged := p.PlugConfigChangedMap[common.PlugTsharkName]
	rpcFwConfigChanged := p.PlugConfigChangedMap[common.PlugRpcFwName]
	ldapFwConfigChanged := p.PlugConfigChangedMap[common.PlugLdapFwName]
	p.mu.RUnlock()

	// check evt plugin thread
	if p.logPluginSwitch {
		if evtAutoRes {
			logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugEvtName)
		} else if !p.plugEvtThread.IsRunning() {
			logger.Infof("try start evt plugin thread")
			if err := p.plugEvtThread.Start(); err != nil {
				logger.Errorf("start evt plugin thread err:%v", err)
			} else {
				p.mu.Lock()
				p.PlugProcessMap[common.PlugEvtName] = 1 // Mark as running (in-process)
				p.mu.Unlock()
			}
		} else {
			// check config change
			if evtConfigChanged {
				logger.Infof("evt plugin config changed, reload evt plugin thread")
				if err := p.plugEvtThread.Reload(); err != nil {
					logger.Errorf("reload evt plugin thread err:%v", err)
					// Don't reset flag on failure - will retry next cycle
				} else {
					p.mu.Lock()
					p.PlugProcessMap[common.PlugEvtName] = 1           // Mark as running (in-process)
					p.PlugConfigChangedMap[common.PlugEvtName] = false // Reset flag ONLY on success
					p.mu.Unlock()
				}
			}
		}
	} else {
		if p.plugEvtThread.IsRunning() {
			logger.Infof("try stop evt plugin thread")
			if err := p.plugEvtThread.Stop(); err != nil {
				logger.Errorf("stop evt plugin thread err:%v", err)
			}
			p.mu.Lock()
			p.PlugProcessMap[common.PlugEvtName] = 0
			p.PlugConfigChangedMap[common.PlugEvtName] = false // Reset flag when stopped
			p.mu.Unlock()
		}
	}

	// check pkt plugin thread
	if p.pktPluginSwitch {
		if pktAutoRes {
			logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugPktName)
		} else if !p.plugPktThread.IsRunning() {
			logger.Infof("try start pkt plugin thread")
			if err := p.plugPktThread.Start(); err != nil {
				logger.Errorf("start pkt plugin thread err:%v", err)
			} else {
				p.mu.Lock()
				p.PlugProcessMap[common.PlugPktName] = 1 // Mark as running (in-process)
				p.mu.Unlock()
			}
		} else {
			// check config change
			if pktConfigChanged {
				logger.Infof("pkt plugin config changed, reload pkt plugin thread")
				if err := p.plugPktThread.Reload(); err != nil {
					logger.Errorf("reload pkt plugin thread err:%v", err)
					// Don't reset flag on failure - will retry next cycle
				} else {
					p.mu.Lock()
					p.PlugProcessMap[common.PlugPktName] = 1           // Mark as running (in-process)
					p.PlugConfigChangedMap[common.PlugPktName] = false // Reset flag ONLY on success
					p.mu.Unlock()
				}
			}
		}
	} else {
		if p.plugPktThread.IsRunning() {
			logger.Infof("try stop pkt plugin thread")
			if err := p.plugPktThread.Stop(); err != nil {
				logger.Errorf("stop pkt plugin thread err:%v", err)
			}
			p.mu.Lock()
			p.PlugProcessMap[common.PlugPktName] = 0
			p.PlugConfigChangedMap[common.PlugPktName] = false // Reset flag when stopped
			p.mu.Unlock()
		}
	}

	// check tshark plugin process
	if p.tsharkPluginSwitch {
		if tsharkAutoRes {
			logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugTsharkName)
		} else if !p.plugTsharkThread.IsRunning() {
			logger.Infof("try start tshark plugin")
			if err := p.plugTsharkThread.Start(); err != nil {
				logger.Errorf("start tshark plugin err:%v", err)
				p.mu.Lock()
				p.PlugProcessMap[common.PlugTsharkName] = 0
				p.mu.Unlock()
			} else {
				p.mu.Lock()
				p.PlugProcessMap[common.PlugTsharkName] = p.plugTsharkThread.PrimaryPID()
				p.PlugConfigChangedMap[common.PlugTsharkName] = false
				p.mu.Unlock()
			}
		} else if tsharkConfigChanged {
			logger.Infof("tshark plugin config changed, reload tshark plugin")
			if err := p.plugTsharkThread.Reload(); err != nil {
				logger.Errorf("reload tshark plugin err:%v", err)
			} else {
				p.mu.Lock()
				p.PlugProcessMap[common.PlugTsharkName] = p.plugTsharkThread.PrimaryPID()
				p.PlugConfigChangedMap[common.PlugTsharkName] = false
				p.mu.Unlock()
			}
		} else {
			p.mu.Lock()
			p.PlugProcessMap[common.PlugTsharkName] = p.plugTsharkThread.PrimaryPID()
			p.mu.Unlock()
		}
	} else {
		if p.plugTsharkThread.IsRunning() {
			logger.Infof("try stop tshark plugin")
			if err := p.plugTsharkThread.Stop(); err != nil {
				logger.Errorf("stop tshark plugin err:%v", err)
			}
			p.mu.Lock()
			p.PlugProcessMap[common.PlugTsharkName] = 0
			p.PlugConfigChangedMap[common.PlugTsharkName] = false
			p.mu.Unlock()
		}
	}

	// check rpc firewall plugin process
	if p.rpcFwPluginSwitch {
		if !isRpcFwInstalled() {
			logger.Warnf("rpc firewall plugin not installed, ignore start")
		} else {
			if rpcFwAutoRes {
				logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugRpcFwName)
			} else if statusMap[common.PlugRpcFwName] == false {
				logger.Infof("try start rpc firewall plugin")
				if err = startRpcFwPlugin(false); err != nil {
					logger.Errorf("start rpc firewall plugin err:%v", err)
				}
			} else {
				if rpcFwConfigChanged {
					logger.Infof("rpc firewall plugin config changed, restart rpc firewall plugin")
					if err = startRpcFwPlugin(true); err != nil {
						logger.Errorf("restart rpc firewall plugin err:%v", err)
					} else {
						p.mu.Lock()
						p.PlugConfigChangedMap[common.PlugRpcFwName] = false // Reset flag ONLY on success
						p.mu.Unlock()
					}
				}
			}
		}
	} else {
		if isRpcFwInstalled() && statusMap[common.PlugRpcFwName] == true {
			logger.Infof("try stop rpc firewall plugin")
			if err = stopRpcFwPlugin(); err != nil {
				logger.Errorf("stop rpc firewall plugin err:%v", err)
			}
			p.mu.Lock()
			p.PlugConfigChangedMap[common.PlugRpcFwName] = false
			p.mu.Unlock()
		}
	}

	// check ldap firewall plugin process
	if p.ldapFwPluginSwitch {
		if !isLdapFwInstalled() {
			logger.Warnf("ldap firewall plugin not installed, ignore start")
		} else {
			if ldapFwAutoRes {
				logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugLdapFwName)
			} else if statusMap[common.PlugLdapFwName] == false {
				logger.Infof("try start ldap firewall plugin")
				if err = startLdapFwPlugin(false); err != nil {
					logger.Errorf("start ldap firewall plugin err:%v", err)
				}
			} else {
				if ldapFwConfigChanged {
					logger.Infof("ldap firewall plugin config changed, restart ldap firewall plugin")
					if err = startLdapFwPlugin(true); err != nil {
						logger.Errorf("restart ldap firewall plugin err:%v", err)
					} else {
						p.mu.Lock()
						p.PlugConfigChangedMap[common.PlugLdapFwName] = false // Reset flag ONLY on success
						p.mu.Unlock()
					}
				}
			}
		}
	} else {
		if isLdapFwInstalled() && statusMap[common.PlugLdapFwName] == true {
			logger.Infof("try stop ldap firewall plugin")
			if err = stopLdapFwPlugin(); err != nil {
				logger.Errorf("stop ldap firewall plugin err:%v", err)
			}
			p.mu.Lock()
			p.PlugConfigChangedMap[common.PlugLdapFwName] = false
			p.mu.Unlock()
		}
	}
}

func (p *Plugin) stopAllPlugin() {
	// Get a snapshot of plugin names to stop
	p.mu.RLock()
	pluginsToStop := make([]string, 0)
	for pluginName, pid := range p.PlugProcessMap {
		if pid > 0 {
			pluginsToStop = append(pluginsToStop, pluginName)
		}
	}
	p.mu.RUnlock()

	for _, pluginName := range pluginsToStop {
		p.stopPlugin(pluginName)
	}
}

func (p *Plugin) stopPlugin(pluginName string) error {
	logger.Infof("Attempting to stop plugin: %s", pluginName)
	var err error
	switch pluginName {
	case common.PlugPktName:
		if p.plugPktThread.IsRunning() {
			err = p.plugPktThread.Stop()
		}
	case common.PlugEvtName:
		if p.plugEvtThread.IsRunning() {
			err = p.plugEvtThread.Stop()
		}
	case common.PlugTsharkName:
		if p.plugTsharkThread.IsRunning() {
			err = p.plugTsharkThread.Stop()
		}
	case common.PlugRpcFwName:
		if isRpcFwInstalled() {
			// Check status before stopping (optional, but good practice)
			statusMap, _ := p.getPluginStatus() // Ignore error for this check
			if statusMap[common.PlugRpcFwName] {
				err = stopRpcFwPlugin()
			}
		}
	case common.PlugLdapFwName:
		if isLdapFwInstalled() {
			// Check status before stopping (optional, but good practice)
			statusMap, _ := p.getPluginStatus() // Ignore error for this check
			if statusMap[common.PlugLdapFwName] {
				err = stopLdapFwPlugin()
			}
		}
	default:
		err = fmt.Errorf("unknown plugin name: %s", pluginName)
	}

	if err == nil {
		// Mark as stopped in the main process map as well
		p.mu.Lock()
		p.PlugProcessMap[pluginName] = 0
		p.mu.Unlock()
		logger.Infof("Plugin %s stopped.", pluginName)
	} else {
		logger.Errorf("Failed to stop plugin %s: %v", pluginName, err)
	}
	return err
}

// AutoResLimit check sensor resource usage, if over limit, stop plugin by priority
// Priority: PlugPktName, PlugLdapFwName, PlugRpcFwName, PlugEvtName
func (p *Plugin) AutoResLimit(wg *sync.WaitGroup) {
	defer wg.Done()

	time.Sleep(60 * time.Second) // Initial delay
	logger.Info("start auto resources limit checker")

	// Priority order for stopping plugins
	pluginStopPriority := []string{
		common.PlugPktName,
		common.PlugTsharkName,
		common.PlugLdapFwName,
		common.PlugRpcFwName,
		common.PlugEvtName,
	}

	for {
		select {
		case <-p.ctx.Done():
			logger.Info("received sensor stop signal, stop auto resources limit checker!")
			return
		case <-time.After(60 * time.Second):
			{
				// Make sure PlugProcessMap is up-to-date before checking stats
				p.getPluginStatus() // Updates p.PlugProcessMap internally

				// Take a snapshot of PlugProcessMap for stats query
				p.mu.RLock()
				processMapSnapshot := make(map[string]uint32)
				for k, v := range p.PlugProcessMap {
					processMapSnapshot[k] = v
				}
				p.mu.RUnlock()

				// Pass the interval duration and context to GetSensorResUsed
				cpuUsed, memUsed, rpcfwCpuUsed, ldapfwCpuUsed, _, _, err := stats.GetSensorResUsed(p.ctx, processMapSnapshot, 30*time.Second)
				if err != nil {
					// Handle context cancellation potentially returned from GetSensorResUsed
					if err == context.Canceled || err == context.DeadlineExceeded {
						logger.Infof("AutoResLimit check cancelled: %v", err)
						return // Exit AutoResLimit loop if context is done
					}
					logger.Warnf("get sensor resources used err:%v, ignore check!", err)
					continue // Skip this check if we can't get stats for other reasons
				}

				limitExceeded := false
				// Compare cpuUsed with p.cpuMaxLimit
				if cpuUsed > p.cpuMaxLimit {
					logger.Warnf("Sensor CPU usage(%f) over than max limit(%f)", cpuUsed, p.cpuMaxLimit)
					limitExceeded = true
				}

				// Compare memUsed with p.memMaxLimit
				if memUsed > p.memMaxLimit {
					logger.Warnf("Sensor Memory usage(%f) over than max limit(%f)", memUsed, p.memMaxLimit)
					limitExceeded = true
				}

				if limitExceeded {
					logger.Warnf("Resource limit exceeded, attempting to stop a plugin...")
					pluginStopped := false

					// Read current state with lock
					p.mu.RLock()
					rpcfwPid := p.PlugProcessMap[common.PlugRpcFwName]
					ldapfwPid := p.PlugProcessMap[common.PlugLdapFwName]
					p.mu.RUnlock()

					// if rpcfw or ldapfw plugin cpu/mem usage over limit, stop it first
					if rpcfwPid > 0 && rpcfwCpuUsed > p.cpuMaxLimit {
						p.stopPlugin(common.PlugRpcFwName)
						logger.Infof("AutoResLimit: Plugin %s stopped successfully.", common.PlugRpcFwName)
						p.mu.Lock()
						p.plugProcessAutoResMap[common.PlugRpcFwName] = true // Mark as stopped by AutoResLimit
						p.mu.Unlock()
						pluginStopped = true
					}

					if ldapfwPid > 0 && ldapfwCpuUsed > p.cpuMaxLimit {
						p.stopPlugin(common.PlugLdapFwName)
						logger.Infof("AutoResLimit: Plugin %s stopped successfully.", common.PlugLdapFwName)
						p.mu.Lock()
						p.plugProcessAutoResMap[common.PlugLdapFwName] = true // Mark as stopped by AutoResLimit
						p.mu.Unlock()
						pluginStopped = true
					}

					for _, pluginName := range pluginStopPriority {
						// Check if plugin is running and not already stopped by this mechanism
						// For in-process plugins (pkt, evt), pid might be 1, for others it's a real PID or 0.
						p.mu.RLock()
						pid := p.PlugProcessMap[pluginName]
						autoStopped := p.plugProcessAutoResMap[pluginName]
						p.mu.RUnlock()

						if pid != 0 && !autoStopped {
							logger.Infof("AutoResLimit: Stopping plugin %s (priority) due to resource limits.", pluginName)
							// Correctly handle the error returned by stopPlugin
							if err := p.stopPlugin(pluginName); err != nil {
								logger.Errorf("AutoResLimit: Failed to stop plugin %s: %v", pluginName, err)
								// Continue trying to stop the next lower priority plugin
							} else {
								logger.Infof("AutoResLimit: Plugin %s stopped successfully.", pluginName)
								p.mu.Lock()
								p.plugProcessAutoResMap[pluginName] = true // Mark as stopped by AutoResLimit
								p.mu.Unlock()
								pluginStopped = true
								break // Stop only one plugin per check cycle
							}
						}
					}
					if !pluginStopped {
						logger.Warn("AutoResLimit: Resource limit exceeded, but no running plugins available to stop according to priority.")
					}
				} else {
					// reset plugProcessAutoResMap
					for _, pluginName := range pluginStopPriority {
						p.mu.RLock()
						autoStopped := p.plugProcessAutoResMap[pluginName]
						p.mu.RUnlock()

						if autoStopped {
							logger.Infof("AutoResLimit: Resetting plugin %s auto res limit flag", pluginName)
							p.mu.Lock()
							p.plugProcessAutoResMap[pluginName] = false
							p.mu.Unlock()
						}
					}
				}
			}
		}
	}
}
