package plugin

import (
	"ada/infra/sanitize"
	"fmt"
	"os/exec"
	"strings"

	logger "github.com/sirupsen/logrus"
)

// 执行阻挡策略

func (p *Plugin) blockPolicyUpdate(data map[string]string) error {
	// 阻挡用户:
	// Set-ADUser -Identity $username -Enabled $false
	// 获取阻挡状态：Get-ADUser -Identity $username -Properties Enabled | Select Enabled

	// 阻挡IP:
	// New-NetFirewallRule -DisplayName "(ADA)Block IP($ip)" -Direction Inbound -Action Block -Protocol Any -RemoteAddress $ip
	// 获取阻挡状态：Get-NetFirewallRule -DisplayName "(ADA)Block IP($ip)"

	logger.Infof("received block policy, data:%v", data)

	userAdd, ok := data["user_add"]
	if !ok {
		logger.Error("user_add not found!")
		return fmt.Errorf("user_add not found")
	}
	ipAdd, ok := data["ip_add"]
	if !ok {
		logger.Error("ip_add not found!")
		return fmt.Errorf("ip_add not found")
	}
	userDel, ok := data["user_del"]
	if !ok {
		logger.Error("user_del not found!")
		return fmt.Errorf("user_del not found")
	}
	ipDel, ok := data["ip_del"]
	if !ok {
		logger.Error("ip_del not found!")
		return fmt.Errorf("ip_del not found")
	}

	var result = make(map[string][]string)

	if len(userAdd) > 0 {
		for _, user := range strings.Split(userAdd, ",") {
			if checkUserBlocked(user) {
				logger.Infof("user(%s) is already blocked, ignore!", user)
				continue
			}
			err := blockingUser(user)
			if err != nil {
				logger.Warnf("blocking user(username:%s) exec failed, err: %v", user, err)
				v, ok := result["blocking_user_failed"]
				if !ok {
					result["blocking_user_failed"] = []string{user}
				} else {
					result["blocking_user_failed"] = append(v, user)
				}
				continue
			}
			logger.Infof("blocking user(%s) exec ok!", user)
		}
	}

	if len(userDel) > 0 {
		for _, user := range strings.Split(userDel, ",") {
			if !checkUserBlocked(user) {
				logger.Infof("user(%s) is already un-blocked, ignore!", user)
				continue
			}
			err := unBlockingUser(user)
			if err != nil {
				logger.Warnf("un-blocking user(username:%s) exec failed, err: %v", user, err)
				v, ok := result["unblocking_user_failed"]
				if !ok {
					result["unblocking_user_failed"] = []string{user}
				} else {
					result["unblocking_user_failed"] = append(v, user)
				}
				continue
			}
			logger.Infof("un-blocking user(%s) exec ok!", user)
		}
	}

	if len(ipAdd) > 0 {
		for _, ip := range strings.Split(ipAdd, ",") {
			if checkIpBlocked(ip) {
				logger.Infof("ip(%s) is already blocked, ignore!", ip)
				continue
			}
			err := blockingIp(ip)
			if err != nil {
				logger.Warnf("blocking ip(ip:%s) exec failed, err: %v", ip, err)
				v, ok := result["blocking_ip_failed"]
				if !ok {
					result["blocking_ip_failed"] = []string{ip}
				} else {
					result["blocking_ip_failed"] = append(v, ip)
				}
				continue
			}
			logger.Infof("blocking ip(%s) exec ok!", ip)
		}
	}

	if len(ipDel) > 0 {
		for _, ip := range strings.Split(ipDel, ",") {
			if !checkIpBlocked(ip) {
				logger.Infof("ip(%s) is already un-blocked, ignore!", ip)
				continue
			}
			err := unBlockingIp(ip)
			if err != nil {
				logger.Warnf("un-blocking ip(ip:%s) exec failed, err: %v", ip, err)
				v, ok := result["unblocking_ip_failed"]
				if !ok {
					result["unblocking_ip_failed"] = []string{ip}
				} else {
					result["unblocking_ip_failed"] = append(v, ip)
				}
				continue
			}
			logger.Infof("un-blocking ip(%s) exec ok!", ip)
		}
	}

	if len(result) > 0 {
		logger.Warnf("block policy exec failed, result: %v", result)
		return fmt.Errorf("block policy exec failed, result: %v", result)
	}

	logger.Info("block policy exec ok!")

	return nil
}

// runPowerShell executes a PowerShell script in a non-interactive session.
//
// PowerShell's -Command switch concatenates every following argument into one
// script string, so values coming from the backend must never be appended as
// separate arguments. Callers validate every value with the sanitize package
// and embed it as a single-quoted literal (sanitize.PowerShellQuote), which
// PowerShell never interpolates.
func runPowerShell(script string) ([]byte, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	return cmd.Output()
}

func firewallRuleName(ip string) string {
	return fmt.Sprintf("(ADA)Block IP(%s)", ip)
}

func checkUserBlocked(username string) bool {
	if err := sanitize.ValidateAccountName(username); err != nil {
		logger.Warnf("refuse to query user(%q): %v", username, err)
		return false
	}
	out, err := runPowerShell("Get-ADUser -Identity " + sanitize.PowerShellQuote(username) + " -Properties Enabled | Select-Object -ExpandProperty Enabled")
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "False")
}

func blockingUser(username string) error {
	if err := sanitize.ValidateAccountName(username); err != nil {
		return fmt.Errorf("refuse to block user %q: %w", username, err)
	}
	out, err := runPowerShell("Set-ADUser -Identity " + sanitize.PowerShellQuote(username) + " -Enabled $false")
	if err != nil {
		logger.Errorf("blocking user(username:%s) exec failed, err: %v, output:%s", username, err, out)
		return err
	}
	return nil
}

func unBlockingUser(username string) error {
	if err := sanitize.ValidateAccountName(username); err != nil {
		return fmt.Errorf("refuse to unblock user %q: %w", username, err)
	}
	out, err := runPowerShell("Set-ADUser -Identity " + sanitize.PowerShellQuote(username) + " -Enabled $true")
	if err != nil {
		logger.Errorf("un-blocking user(username:%s) exec failed, err: %v, output:%s", username, err, out)
		return err
	}
	return nil
}

func checkIpBlocked(ip string) bool {
	if _, err := sanitize.ValidateIPOrCIDR(ip); err != nil {
		logger.Warnf("refuse to query firewall rule for ip(%q): %v", ip, err)
		return false
	}
	_, err := runPowerShell("Get-NetFirewallRule -DisplayName " + sanitize.PowerShellQuote(firewallRuleName(ip)))
	return err == nil
}

func blockingIp(ip string) error {
	if _, err := sanitize.ValidateIPOrCIDR(ip); err != nil {
		return fmt.Errorf("refuse to block ip %q: %w", ip, err)
	}
	script := "New-NetFirewallRule -DisplayName " + sanitize.PowerShellQuote(firewallRuleName(ip)) +
		" -Direction Inbound -Action Block -Protocol Any -RemoteAddress " + sanitize.PowerShellQuote(ip)
	out, err := runPowerShell(script)
	if err != nil {
		logger.Errorf("blocking ip(ip:%s) exec failed, err: %v, output:%s", ip, err, out)
		return err
	}
	return nil
}

func unBlockingIp(ip string) error {
	if _, err := sanitize.ValidateIPOrCIDR(ip); err != nil {
		return fmt.Errorf("refuse to unblock ip %q: %w", ip, err)
	}
	out, err := runPowerShell("Remove-NetFirewallRule -DisplayName " + sanitize.PowerShellQuote(firewallRuleName(ip)))
	if err != nil {
		logger.Errorf("un-blocking ip(ip:%s) exec failed, err: %v, output:%s", ip, err, out)
		return err
	}
	return nil
}
