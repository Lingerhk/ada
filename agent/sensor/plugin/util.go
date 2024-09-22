package plugin

import (
	"ada/agent/sensor/common"
	"crypto/sha256"
	"fmt"
	sigar "github.com/cloudfoundry/gosigar"
	"github.com/shirou/gopsutil/process"
	logger "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"
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
	statusMap["self"] = false // ADA Sensor(ada_sensor)
	statusMap[common.PlugNxlogName] = false
	statusMap[common.PlugRpcFwName] = false  // RPC Firewall
	statusMap[common.PlugLdapFwName] = false // LDAP Firewall

	var s *mgr.Service
	var svcFindName string
	for svcName, _ := range statusMap {
		switch svcName {
		case "self":
			svcFindName = common.SensorSvcName
		case common.PlugNxlogName:
			svcFindName = common.PlugNxlogSvcName
		case common.PlugRpcFwName:
			svcFindName = common.PlugRpcFwSvcName
		case common.PlugLdapFwName:
			svcFindName = common.PlugLdapFwSvcName
		default:
			svcFindName = svcName
		}

		p.PlugProcessMap[svcName] = 0 // 先将进程名

		s, err = m.OpenService(svcFindName)
		if err != nil {
			logger.Warnf("open service %s err:%v", svcName, err)
			continue
		}

		statusCode, err := s.Query()
		if err != nil {
			logger.Warnf("query service %s err:%v", svcName, err)
			continue
		}
		if statusCode.State == svc.Running {
			statusMap[svcName] = true
			p.PlugProcessMap[svcName] = statusCode.ProcessId
		}
		s.Close()
	}

	return statusMap, nil
}

func startNxlogPlugin(restart bool) error {
	cmd := exec.Command("powershell.exe", "-Command", "Start-Service", "-Name", "nxlog")
	if restart {
		cmd = exec.Command("powershell.exe", "-Command", "Restart-Service", "-Name", "nxlog")
	}

	return cmd.Start()
}

func stopNxlogPlugin() error {
	cmd := exec.Command("powershell.exe", "-Command", "Stop-Service", "-Name", "nxlog")
	return cmd.Start()
}

func startRpcFwPlugin(restart bool) error {
	if restart {
		cmd := exec.Command(rpcFwBinPath, "/stop")
		_ = cmd.Start()
	}

	cmd := exec.Command(rpcFwBinPath, "/start")
	return cmd.Start()
}

func stopRpcFwPlugin() error {
	cmd := exec.Command(rpcFwBinPath, "/stop")
	return cmd.Start()
}

func reloadRpcFwPlugin() error {
	cmd := exec.Command(rpcFwBinPath, "/update")
	return cmd.Start()
}

func startLdapFwPlugin(restart bool) error {
	if restart {
		err := stopLdapFwPlugin()
		if err != nil {
			return err
		}
	}

	cmd := exec.Command("powershell.exe", "-Command", "Start-Service", "-Name", `"LDAP Firewall"`)
	return cmd.Start()
}

func stopLdapFwPlugin() error {
	// 	powershell exec: Stop-Service -name "LDAP Firewall"
	cmd := exec.Command("powershell.exe", "-Command", "Stop-Service", "-Name", `"LDAP Firewall"`)
	return cmd.Start()
}

func reloadLdapFwPlugin() error {
	cmd := exec.Command(ldapFwBinPath, "/update")
	return cmd.Start()
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

	if err := ioutil.WriteFile("sensor.cfg", []byte(sensorCfg), 0644); err != nil {
		logger.Errorf("write sensor.cfg file err:%v", err)
		return err
	}

	// TODO: how to restart self service????
	cmd := exec.Command("powershell.exe", "-Command", "Restart-Service", "-Name", common.SensorSvcName)
	return cmd.Start()
}

// pluginConfUpdate 执行plugin的配置文件更新
// 支持的配置文件:
// nxlog: nxlog.conf
// rpcfw: RpcFw.conf
// ldapfw: config.json
func (p *Plugin) pluginConfUpdate(data map[string]string) error {
	var err error

	if nxlogCfg, ok := data["nxlog.conf"]; ok {
		if !p.checkFileSum(nxlogCfg, data["nxlog.conf.sha256"]) {
			logger.Error("check file(nxlog.conf) sum failed")
		} else {
			nxlogCfgFile := filepath.Join(common.SensorDir, "nxlog", "conf", "nxlog.conf")
			if err = ioutil.WriteFile(nxlogCfgFile, []byte(nxlogCfg), 0644); err != nil {
				logger.Errorf("write %s file err:%v", nxlogCfgFile, err)
			} else {
				if err = startNxlogPlugin(true); err != nil {
					logger.Errorf("reload nxlog plugin err:%v", err)
				}
			}
		}
	}

	if rpcfwCfg, ok := data["rpcFw.conf"]; ok {
		if !p.checkFileSum(rpcfwCfg, data["rpcFw.conf.sha256"]) {
			logger.Error("check file(rpcFw.conf) sum failed")
		} else {
			rpcfwCfgFile := filepath.Join(common.SensorDir, "rpcfw", "rpcFw.conf")
			if err = ioutil.WriteFile(rpcfwCfgFile, []byte(rpcfwCfg), 0644); err != nil {
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
			if err = ioutil.WriteFile(ldapfwCfgFile, []byte(ldapfwCfg), 0644); err != nil {
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

// Try to kill the orphan process(windows)
func TryKillProcess(processName string) error {
	processPid, err := getProcessPidByName(processName)
	if err != nil {
		return err
	}
	if processPid == -1 {
		return nil
	}

	proc, err := process.NewProcess(int32(processPid))
	if err != nil {
		return err
	}

	if err := proc.Kill(); err != nil {
		return err
	}

	return nil
}

// Try to kill the orphan service(windows)
func TryStopService(serviceName string) error {
	var err error
	switch serviceName {
	case common.PlugNxlogName:
		err = stopNxlogPlugin()
	case common.PlugRpcFwName:
		err = stopRpcFwPlugin()
	case common.PlugLdapFwName:
		err = stopLdapFwPlugin()
	}

	return err
}

func getProcessPidByName(processName string) (int, error) {
	pids := sigar.ProcList{}
	err := pids.Get()
	if err != nil {
		return 0, err
	}

	for _, pid := range pids.List {
		state := sigar.ProcState{}
		if err := state.Get(pid); err != nil {
			continue
		}
		if strings.ToUpper(state.Name) == strings.ToUpper(processName) {
			return pid, nil
		}
	}

	return -1, nil
}

func (p *Plugin) checkFileSum(fileCnt, sha265sum string) bool {
	hash := sha256.New()
	hash.Write([]byte(fileCnt))
	sumStr := fmt.Sprintf("%x", hash.Sum(nil))

	return sumStr == sha265sum
}
