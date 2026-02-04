package plugin

import (
	"ada/agent/sensor/common"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	logger "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

var (
	rpcFwBinPath  = filepath.Join(common.SensorDir, "rpcfw", common.PlugRpcFwProcName)
	ldapFwBinPath = filepath.Join(common.SensorDir, "ldapfw", common.PlugLdapFwProcName)
)

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
	if restart {
		// Wait for stop to complete before starting
		cmd := exec.Command(rpcFwBinPath, "/stop")
		if err := cmd.Run(); err != nil {
			logger.Warnf("stop rpcfw before restart err: %v", err)
			// Continue with start anyway
		}
	}

	cmd := exec.Command(rpcFwBinPath, "/start")
	return cmd.Run()
}

func stopRpcFwPlugin() error {
	cmd := exec.Command(rpcFwBinPath, "/stop")
	return cmd.Run()
}

func reloadRpcFwPlugin() error {
	cmd := exec.Command(rpcFwBinPath, "/update")
	return cmd.Run()
}

func isLdapFwInstalled() bool {
	_, err := os.Stat(ldapFwBinPath)
	if err != nil && !os.IsExist(err) {
		return false
	}

	return true
}

func startLdapFwPlugin(restart bool) error {
	if restart {
		// Wait for stop to complete before starting
		if err := stopLdapFwPlugin(); err != nil {
			logger.Warnf("stop ldapfw before restart err: %v", err)
			// Continue with start anyway
		}
	}

	cmd := exec.Command("powershell.exe", "-Command", "Start-Service", "-Name", `"LDAP Firewall"`)
	return cmd.Run()
}

func stopLdapFwPlugin() error {
	// powershell exec: Stop-Service -name "LDAP Firewall"
	cmd := exec.Command("powershell.exe", "-Command", "Stop-Service", "-Name", `"LDAP Firewall"`)
	return cmd.Run()
}

func reloadLdapFwPlugin() error {
	cmd := exec.Command(ldapFwBinPath, "/update")
	return cmd.Run()
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
			rpcfwCfgFile := filepath.Join(common.SensorDir, "rpcfw", "rpcFw.conf")
			if err = os.WriteFile(rpcfwCfgFile, []byte(rpcfwCfg), 0644); err != nil {
				logger.Errorf("write %s file err:%v", rpcfwCfgFile, err)
			} else {
				// reload rpcfw
				if err = reloadRpcFwPlugin(); err != nil {
					logger.Errorf("reload rpcfw plugin err:%v", err)
				}
			}
		}
	}

	if ldapfwCfg, ok := data["config.json"]; ok {
		if !p.checkFileSum(ldapfwCfg, data["config.json.sha256"]) {
			logger.Error("check file(config.json) sum failed")
		} else {
			ldapfwCfgFile := filepath.Join(common.SensorDir, "ldapfw", "config.json")
			if err = os.WriteFile(ldapfwCfgFile, []byte(ldapfwCfg), 0644); err != nil {
				logger.Errorf("write %s file err:%v", ldapfwCfgFile, err)
			} else {
				// reload ldapfw
				if err = reloadLdapFwPlugin(); err != nil {
					logger.Errorf("reload ldapfw plugin err:%v", err)
				}
			}
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
