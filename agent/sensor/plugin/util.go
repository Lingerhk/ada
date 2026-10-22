//go:build windows

package plugin

import (
	"ada/agent/sensor/common"
	"ada/agent/sensor/fwmgr"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	logger "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	rpcFwBinPath  = filepath.Join(common.SensorDir, "rpcfw", common.PlugRpcFwProcName)
	ldapFwBinPath = filepath.Join(common.SensorDir, "ldapfw", common.PlugLdapFwProcName)

	rpcFwConfPath  = filepath.Join(common.SensorDir, "rpcfw", "rpcFw.conf")
	ldapFwConfPath = filepath.Join(common.SensorDir, "ldapfw", "config.json")
)

// managerCmdTimeout bounds a single firewall manager invocation (service
// control or config reload) so a hung manager cannot stall the plugin loop,
// unlike the previous unbounded exec.Command calls.
const managerCmdTimeout = 60 * time.Second

func rpcFwManager() *fwmgr.Manager  { return fwmgr.NewRPC(rpcFwBinPath, rpcFwConfPath) }
func ldapFwManager() *fwmgr.Manager { return fwmgr.NewLDAP(ldapFwBinPath, ldapFwConfPath) }

func managerContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), managerCmdTimeout)
}

// firewallProtectionActive reports whether the firewall's event log shows
// protection is currently applied. ok is false when the state could not be
// determined (e.g. the event channel is unreadable), in which case callers
// should fall back to the plain service-running signal rather than assume a
// state.
func firewallProtectionActive(m *fwmgr.Manager) (active, ok bool) {
	ctx, cancel := managerContext()
	defer cancel()
	a, err := m.ProtectionActive(ctx)
	if err != nil {
		logger.Warnf("determine %s protection state err:%v", m.Name(), err)
		return false, false
	}
	return a, true
}

func (p *Plugin) getPluginStatus() (map[string]bool, error) {
	m, err := mgr.Connect()
	if err != nil {
		return nil, err
	}
	defer m.Disconnect()

	statusMap := make(map[string]bool)
	statusMap[common.SensorSvcName] = false // ADA Sensor(ada_sensor)

	if isRpcFwInstalled() {
		statusMap[common.PlugRpcFwName] = false // RPC Firewall
	}
	if isLdapFwInstalled() {
		statusMap[common.PlugLdapFwName] = false // LDAP Firewall
	}

	var s *mgr.Service
	var svcFindName string
	for svcName := range statusMap {
		switch svcName {
		case common.SensorSvcName:
			svcFindName = common.SensorSvcName
		case common.PlugRpcFwName:
			svcFindName = common.PlugRpcFwSvcName
		case common.PlugLdapFwName:
			svcFindName = common.PlugLdapFwSvcName
		default:
			svcFindName = svcName
		}

		// Reset process ID with lock
		p.mu.Lock()
		p.PlugProcessMap[svcName] = 0
		p.mu.Unlock()

		s, err = m.OpenService(svcFindName)
		if err != nil {
			// if the ada sensor run in terminal, the service is not running
			if svcName == common.SensorSvcName {
				statusMap[svcName] = true

				// get self process id
				pid := os.Getpid()
				p.mu.Lock()
				p.PlugProcessMap[svcName] = uint32(pid)
				p.mu.Unlock()
				continue
			}

			logger.Warnf("open service %s err:%v", svcName, err)
			continue
		}

		statusCode, err := s.Query()
		if err != nil {
			logger.Warnf("query service %s err:%v", svcName, err)
			s.Close()
			continue
		}
		if statusCode.State == svc.Running {
			statusMap[svcName] = true
			p.mu.Lock()
			p.PlugProcessMap[svcName] = statusCode.ProcessId
			p.mu.Unlock()
		}
		s.Close()
	}

	// A firewall service can be running while protection is not actually
	// applied (e.g. injection failed). Judge "up" by the firewall's own
	// event log; when it shows protection is NOT applied, report the plugin
	// as down so runPlugin re-applies it. On an unreadable log, keep the
	// service-running signal.
	if statusMap[common.PlugRpcFwName] {
		if active, ok := firewallProtectionActive(rpcFwManager()); ok && !active {
			logger.Warnf("rpcfw service running but protection not applied; will re-apply")
			statusMap[common.PlugRpcFwName] = false
		}
	}
	if statusMap[common.PlugLdapFwName] {
		if active, ok := firewallProtectionActive(ldapFwManager()); ok && !active {
			logger.Warnf("ldapfw service running but protection not applied; will re-apply")
			statusMap[common.PlugLdapFwName] = false
		}
	}

	return statusMap, nil
}

func isRpcFwInstalled() bool {
	_, err := os.Stat(rpcFwBinPath)
	if err != nil && !os.IsExist(err) {
		return false
	}

	return true
}

func startRpcFwPlugin(restart bool) error {
	ctx, cancel := managerContext()
	defer cancel()
	m := rpcFwManager()
	if restart {
		if err := m.Stop(ctx); err != nil {
			logger.Warnf("stop rpcfw before restart err: %v", err)
		}
	}
	return m.Start(ctx)
}

func stopRpcFwPlugin() error {
	ctx, cancel := managerContext()
	defer cancel()
	return rpcFwManager().Stop(ctx)
}

func isLdapFwInstalled() bool {
	_, err := os.Stat(ldapFwBinPath)
	if err != nil && !os.IsExist(err) {
		return false
	}

	return true
}

func startLdapFwPlugin(restart bool) error {
	ctx, cancel := managerContext()
	defer cancel()
	m := ldapFwManager()
	if restart {
		if err := m.Stop(ctx); err != nil {
			logger.Warnf("stop ldapfw before restart err: %v", err)
		}
	}
	return m.Start(ctx)
}

func stopLdapFwPlugin() error {
	ctx, cancel := managerContext()
	defer cancel()
	return ldapFwManager().Stop(ctx)
}

func (p *Plugin) sensorConfUpdate(data map[string]string) error {
	// 优先判断是否存在`sensor.cfg`，存在则覆盖配置文件，否则check是否存在配置参数
	sensorCfg, ok := data["sensor.cfg"]
	if !ok {
		return fmt.Errorf("no config option update, data:%v", data)
	}

	if !p.checkFileSum(sensorCfg, data["sensor.cfg.sha256"]) {
		return fmt.Errorf("check file(sensor.cfg) sum(%s) failed", data["sensor.cfg.sha256"])
	}

	// Use absolute path to ensure config file is written to correct location
	cfgFilePath := filepath.Join(common.SensorDir, "sensor.cfg")
	if err := os.WriteFile(cfgFilePath, []byte(sensorCfg), 0644); err != nil {
		logger.Errorf("write sensor.cfg file err:%v", err)
		return err
	}

	// Restart self service - use Start() here since we want to exit before restart completes
	cmd := exec.Command("powershell.exe", "-Command", "Restart-Service", "-Name", common.SensorSvcName)
	return cmd.Start()
}

// pluginConfUpdate 执行plugin的配置文件更新
// 支持的配置文件:
// rpcfw: RpcFw.conf
// ldapfw: config.json
func (p *Plugin) pluginConfUpdate(data map[string]string) error {
	var err error

	if rpcfwCfg, ok := data["rpcFw.conf"]; ok {
		if !p.checkFileSum(rpcfwCfg, data["rpcFw.conf.sha256"]) {
			logger.Error("check file(rpcFw.conf) sum failed")
		} else {
			// ApplyConfig validates the config, writes it atomically and asks
			// the firewall to reload, rolling back on a rejected reload.
			ctx, cancel := managerContext()
			if e := rpcFwManager().ApplyConfig(ctx, []byte(rpcfwCfg)); e != nil {
				logger.Errorf("apply rpcfw config err:%v", e)
				err = e
			}
			cancel()
		}
	}

	if ldapfwCfg, ok := data["config.json"]; ok {
		if !p.checkFileSum(ldapfwCfg, data["config.json.sha256"]) {
			logger.Error("check file(config.json) sum failed")
		} else {
			ctx, cancel := managerContext()
			if e := ldapFwManager().ApplyConfig(ctx, []byte(ldapfwCfg)); e != nil {
				logger.Errorf("apply ldapfw config err:%v", e)
				err = e
			}
			cancel()
		}
	}

	return err
}

// pluginBinUpdate 执行plugin的二进制程序更新
// 仅支持rpcfw和ldapfw更新, 格式为.zip
func (p *Plugin) pluginBinUpdate(data map[string]string) error {
	//var err error

	if rpcfwPkg, ok := data["rpcfw.zip"]; ok {
		if !p.checkFileSum(rpcfwPkg, data["rpcfw.zip.sha256"]) {
			logger.Error("check file(rpcfw.zip) sum failed")
		} else {
			// TODO:
			// stop rpcfw plugin first

			// replase new rpcfw bin file

			// start  rpcfw plugin
		}
	}

	if ldapfwPkg, ok := data["ldapfw.zip"]; ok {
		if !p.checkFileSum(ldapfwPkg, data["ldapfw.zip.sha256"]) {
			logger.Error("check file(ldapfw.zip) sum failed")
		} else {
			// TODO:
			// stop rpcfw plugin first

			// replase new rpcfw bin file

			// start  rpcfw plugin
		}
	}

	return nil
}

// Try to kill the orphan service(windows)
func TryStopService(serviceName string) error {
	var err error
	switch serviceName {
	case common.PlugRpcFwName:
		err = stopRpcFwPlugin()
	case common.PlugLdapFwName:
		err = stopLdapFwPlugin()
	}

	return err
}

func (p *Plugin) checkFileSum(fileCnt, sha265sum string) bool {
	hash := sha256.New()
	hash.Write([]byte(fileCnt))
	sumStr := fmt.Sprintf("%x", hash.Sum(nil))

	return sumStr == sha265sum
}
