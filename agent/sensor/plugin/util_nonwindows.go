//go:build !windows

package plugin

import (
	"ada/agent/sensor/common"
	"fmt"
)

var (
	rpcFwBinPath  = ""
	ldapFwBinPath = ""
)

func (p *Plugin) getPluginStatus() (map[string]bool, error) {
	statusMap := map[string]bool{
		common.SensorSvcName:   false,
		common.PlugRpcFwName:   false,
		common.PlugLdapFwName:  false,
		common.PlugPktName:     false,
		common.PlugEvtName:     false,
	}
	return statusMap, nil
}

func isRpcFwInstalled() bool {
	return false
}

func isLdapFwInstalled() bool {
	return false
}

func startRpcFwPlugin(restart bool) error {
	return fmt.Errorf("rpc firewall plugin is only supported on windows")
}

func stopRpcFwPlugin() error {
	return fmt.Errorf("rpc firewall plugin is only supported on windows")
}

func reloadRpcFwPlugin() error {
	return fmt.Errorf("rpc firewall plugin is only supported on windows")
}

func startLdapFwPlugin(restart bool) error {
	return fmt.Errorf("ldap firewall plugin is only supported on windows")
}

func stopLdapFwPlugin() error {
	return fmt.Errorf("ldap firewall plugin is only supported on windows")
}

func reloadLdapFwPlugin() error {
	return fmt.Errorf("ldap firewall plugin is only supported on windows")
}

func (p *Plugin) sensorConfUpdate(data map[string]string) error {
	return fmt.Errorf("sensor configuration update is only supported on windows")
}

func (p *Plugin) pluginConfUpdate(data map[string]string) error {
	return fmt.Errorf("plugin configuration update is only supported on windows")
}

func (p *Plugin) pluginBinUpdate(data map[string]string) error {
	return fmt.Errorf("plugin binary update is only supported on windows")
}

func TryStopService(serviceName string) error {
	return nil
}
