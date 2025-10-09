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
	rpcFwPluginSwitch  bool
	ldapFwPluginSwitch bool
	cpuMaxLimit        float64
	memMaxLimit        float64

	plugEvtThread         *evtPlugin
	plugPktThread         *pktPlugin
	PlugProcessMap        map[string]uint32
	PlugConfigChangedMap  map[string]bool // 记录插件配置是否发生变化
	plugProcessAutoResMap map[string]bool // Track plugins stopped by AutoResLimit
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
	plugProcessMap[common.PlugRpcFwName] = 0
	plugProcessMap[common.PlugLdapFwName] = 0
	plug.PlugProcessMap = plugProcessMap

	plugConfigChangedMap := make(map[string]bool)
	plugConfigChangedMap[common.PlugEvtName] = false
	plugConfigChangedMap[common.PlugPktName] = false
	plugConfigChangedMap[common.PlugRpcFwName] = false
	plugConfigChangedMap[common.PlugLdapFwName] = false
	plug.PlugConfigChangedMap = plugConfigChangedMap

	plugProcessAutoResMap := make(map[string]bool)
	plugProcessAutoResMap[common.PlugPktName] = false
	plugProcessAutoResMap[common.PlugEvtName] = false
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
	for pluginName, _ := range p.PlugConfigChangedMap {
		p.PlugConfigChangedMap[pluginName] = false
	}

	sensorIDKey := fmt.Sprintf("%s:%s", common.SensorIDPrefixKey, p.sensorId)

	if p.plugProcessAutoResMap[common.PlugPktName] {
		logger.Infof("pkt plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigurePktPlugin(sensorIDKey)
	}

	if p.plugProcessAutoResMap[common.PlugEvtName] {
		logger.Infof("evt plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigureEvtPlugin(sensorIDKey)
	}

	if p.plugProcessAutoResMap[common.PlugRpcFwName] {
		logger.Infof("rpcfw plugin auto res limit flag is true, ignore load configure")
	} else {
		p.loadConfigureRpcFwPlugin(sensorIDKey)
	}

	if p.plugProcessAutoResMap[common.PlugLdapFwName] {
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
			if p.plugEvtThread.EventFilter != v {
				logger.Infof("log event filter changed to %v", v)
				p.PlugConfigChangedMap[common.PlugEvtName] = true
				p.plugEvtThread.EventFilter = v
			}
		}
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

	// check evt plugin thread
	if p.logPluginSwitch {
		if p.plugProcessAutoResMap[common.PlugEvtName] {
			logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugEvtName)
		} else if !p.plugEvtThread.IsRunning() {
			logger.Infof("try start evt plugin thread")
			if err := p.plugEvtThread.Start(); err != nil {
				logger.Errorf("start evt plugin thread err:%v", err)
			} else {
				p.PlugProcessMap[common.PlugEvtName] = 1 // Mark as running (in-process)
			}
		} else {
			// check config change
			if p.PlugConfigChangedMap[common.PlugEvtName] {
				logger.Infof("evt plugin config changed, reload evt plugin thread")
				if err := p.plugEvtThread.Reload(); err != nil {
					logger.Errorf("reload evt plugin thread err:%v", err)
				} else {
					p.PlugProcessMap[common.PlugEvtName] = 1 // Mark as running (in-process)
				}
			}
		}
	} else {
		if p.plugEvtThread.IsRunning() {
			logger.Infof("try stop evt plugin thread")
			if err := p.plugEvtThread.Stop(); err != nil {
				logger.Errorf("stop evt plugin thread err:%v", err)
			}
			p.PlugProcessMap[common.PlugEvtName] = 0
		}
	}

	// check pkt plugin thread
	if p.pktPluginSwitch {
		if p.plugProcessAutoResMap[common.PlugPktName] {
			logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugPktName)
		} else if !p.plugPktThread.IsRunning() {
			logger.Infof("try start pkt plugin thread")
			if err := p.plugPktThread.Start(); err != nil {
				logger.Errorf("start pkt plugin thread err:%v", err)
			} else {
				p.PlugProcessMap[common.PlugPktName] = 1 // Mark as running (in-process)
			}
		} else {
			// check config change
			if p.PlugConfigChangedMap[common.PlugPktName] {
				logger.Infof("pkt plugin config changed, reload pkt plugin thread")
				if err := p.plugPktThread.Reload(); err != nil {
					logger.Errorf("reload pkt plugin thread err:%v", err)
				} else {
					p.PlugProcessMap[common.PlugPktName] = 1 // Mark as running (in-process)
				}
			}
		}
	} else {
		if p.plugPktThread.IsRunning() {
			logger.Infof("try stop pkt plugin thread")
			if err := p.plugPktThread.Stop(); err != nil {
				logger.Errorf("stop pkt plugin thread err:%v", err)
			}
			p.PlugProcessMap[common.PlugPktName] = 0
		}
	}

	// check rpc firewall plugin process
	if p.rpcFwPluginSwitch {
		if !isRpcFwInstalled() {
			logger.Warnf("rpc firewall plugin not installed, ignore start")
		} else {
			if p.plugProcessAutoResMap[common.PlugRpcFwName] {
				logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugRpcFwName)
			} else if statusMap[common.PlugRpcFwName] == false {
				logger.Infof("try start rpc firewall plugin")
				if err = startRpcFwPlugin(false); err != nil {
					logger.Errorf("start rpc firewall plugin err:%v", err)
				}
			} else {
				if p.PlugConfigChangedMap[common.PlugRpcFwName] {
					logger.Infof("rpc firewall plugin config changed, restart rpc firewall plugin")
					if err = startRpcFwPlugin(true); err != nil {
						logger.Errorf("restart rpc firewall plugin err:%v", err)
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
		}
	}

	// check ldap firewall plugin process
	if p.ldapFwPluginSwitch {
		if !isLdapFwInstalled() {
			logger.Warnf("ldap firewall plugin not installed, ignore start")
		} else {
			if p.plugProcessAutoResMap[common.PlugLdapFwName] {
				logger.Warnf("Plugin %s start skipped due to AutoResLimit", common.PlugLdapFwName)
			} else if statusMap[common.PlugLdapFwName] == false {
				logger.Infof("try start ldap firewall plugin")
				if err = startLdapFwPlugin(false); err != nil {
					logger.Errorf("start ldap firewall plugin err:%v", err)
				}
			} else {
				if p.PlugConfigChangedMap[common.PlugLdapFwName] {
					logger.Infof("ldap firewall plugin config changed, restart ldap firewall plugin")
					if err = startLdapFwPlugin(true); err != nil {
						logger.Errorf("restart ldap firewall plugin err:%v", err)
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
		}
	}
}

func (p *Plugin) stopAllPlugin() {
	for pluginName, _ := range p.PlugProcessMap {
		if p.PlugProcessMap[pluginName] > 0 {
			p.stopPlugin(pluginName)
		}
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
		p.PlugProcessMap[pluginName] = 0
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

				// Pass the interval duration and context to GetSensorResUsed
				cpuUsed, memUsed, rpcfwCpuUsed, ldapfwCpuUsed, _, _, err := stats.GetSensorResUsed(p.ctx, p.PlugProcessMap, 30*time.Second)
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

					// if rpcfw or ldapfw plugin cpu/mem usage over limit, stop it first
					if p.PlugProcessMap[common.PlugRpcFwName] > 0 && rpcfwCpuUsed > p.cpuMaxLimit {
						p.stopPlugin(common.PlugRpcFwName)
						logger.Infof("AutoResLimit: Plugin %s stopped successfully.", common.PlugRpcFwName)
						p.plugProcessAutoResMap[common.PlugRpcFwName] = true // Mark as stopped by AutoResLimit
						pluginStopped = true
					}

					if p.PlugProcessMap[common.PlugLdapFwName] > 0 && ldapfwCpuUsed > p.cpuMaxLimit {
						p.stopPlugin(common.PlugLdapFwName)
						logger.Infof("AutoResLimit: Plugin %s stopped successfully.", common.PlugLdapFwName)
						p.plugProcessAutoResMap[common.PlugLdapFwName] = true // Mark as stopped by AutoResLimit
						pluginStopped = true
					}

					for _, pluginName := range pluginStopPriority {
						// Check if plugin is running and not already stopped by this mechanism
						// For in-process plugins (pkt, evt), pid might be 1, for others it's a real PID or 0.
						if pid, running := p.PlugProcessMap[pluginName]; running && pid != 0 {
							if autoStopped, exists := p.plugProcessAutoResMap[pluginName]; exists && !autoStopped {
								logger.Infof("AutoResLimit: Stopping plugin %s (priority) due to resource limits.", pluginName)
								// Correctly handle the error returned by stopPlugin
								if err := p.stopPlugin(pluginName); err != nil {
									logger.Errorf("AutoResLimit: Failed to stop plugin %s: %v", pluginName, err)
									// Continue trying to stop the next lower priority plugin
								} else {
									logger.Infof("AutoResLimit: Plugin %s stopped successfully.", pluginName)
									p.plugProcessAutoResMap[pluginName] = true // Mark as stopped by AutoResLimit
									pluginStopped = true
									break // Stop only one plugin per check cycle
								}
							}
						}
					}
					if !pluginStopped {
						logger.Warn("AutoResLimit: Resource limit exceeded, but no running plugins available to stop according to priority.")
					}
				} else {
					// reset plugProcessAutoResMap
					for _, pluginName := range pluginStopPriority {
						if autoStopped, exists := p.plugProcessAutoResMap[pluginName]; exists && autoStopped {
							logger.Infof("AutoResLimit: Resetting plugin %s auto res limit flag", pluginName)
							p.plugProcessAutoResMap[pluginName] = false
						}
					}
				}
			}
		}
	}
}
