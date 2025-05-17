package service

import (
	"ada/backend/apiserver/api/rpc"
	"ada/infra/net"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/masterzen/winrm"
	logger "github.com/sirupsen/logrus"
)

func (s *ADAServiceV2) syncDomainStatus(ctx context.Context) (string, error) {
	// after uninstall sensor, need to sync domain
	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err != nil {
		logger.Errorf("new rpc client err:%v", err)
		return "", err
	}

	defer client.Close()
	taskId, err := client.DomainStatusSyncTask()
	if err != nil {
		logger.Warnf("send domain status sync task err:%v", err)
		return "", err
	}

	return taskId, nil
}

func getWinRMClient(ctx context.Context, dcIP, username, password string) (*winrm.Client, error) {
	defaultTimeout := 600 * time.Second

	winrmConfig := winrm.NewEndpoint(
		dcIP,           // Host
		5985,           // Port (HTTP)
		false,          // TLS
		false,          // InsecureSkipVerify
		nil,            // CACert
		nil,            // Cert
		nil,            // Key
		defaultTimeout, // Timeout in seconds
	)

	winrmClient, err := winrm.NewClient(winrmConfig, username, password)
	if err != nil {
		logger.Errorf("create winrm client err:%v", err)
		return nil, err
	}

	return winrmClient, nil
}

// getValidDCServerIP get a valid DC server IP from the list
func getValidDCServerIP(dcIPList []string) string {
	var dcIP string
	// // if IPList is more than 1, then using socket to get the available IP
	if len(dcIPList) > 1 {
		for _, ip := range dcIPList {
			addr, err := netip.ParseAddr(ip)
			if err == nil && addr.Is6() { // ignore ipv6
				continue
			}

			// Check if port 5985 (WinRM HTTP) is open
			isOpen, _ := net.CheckPortOpen(ip, 5985)
			if isOpen {
				dcIP = ip
				break
			}
		}
		if dcIP == "" {

		}
	} else {
		dcIP = dcIPList[0]
	}

	return dcIP
}

func (s *ADAServiceV2) winRMInstallSensor(ctx context.Context, dcIPs []string, adaServerIP, username, password string) (string, error) {
	dcIP := getValidDCServerIP(dcIPs)

	winrmClient, err := getWinRMClient(ctx, dcIP, username, password)
	if err != nil {
		logger.Errorf("get winrm client err:%v", err)
		return "", err
	}

	// update adaegis server address in install-adaegis.ps1
	curDir, _ := os.Getwd()
	installScriptFile := filepath.Join(curDir, "../download/sensor", "install-adaegis.ps1")
	if _, err := os.Stat(installScriptFile); err != nil {
		logger.Errorf("install script(%s) not found, skip deploy sensor", installScriptFile)
		return "", err
	}

	installScriptBytes, err := os.ReadFile(installScriptFile)
	if err != nil {
		logger.Errorf("read install script(%s) err:%v", installScriptFile, err)
		return "", err
	}

	installScriptContent := strings.ReplaceAll(string(installScriptBytes), "YOUR_ADA_SERVER_IP", adaServerIP)
	err = os.WriteFile(installScriptFile, []byte(installScriptContent), 0644)
	if err != nil {
		logger.Errorf("write modified install script(%s) err:%v", installScriptFile, err)
		return "", err
	}

	// Prepare download command for the installation script
	downloadCmd := fmt.Sprintf(`Invoke-WebRequest -Uri "http://%s/download/sensor/install-adaegis.ps1" -OutFile "C:\install-adaegis.ps1"`, adaServerIP)
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger.Infof("winrm(dc ip:%s, username:%s) downloadCmd:%s", dcIP, username, downloadCmd)

	// Execute download command
	downloadStdout, downloadStderr, downloadCode, err := winrmClient.RunPSWithContext(execCtx, downloadCmd)
	if err != nil || downloadCode != 0 {
		logger.Errorf("run download script err:%v, code:%d, stdout:%s, stderr:%s",
			err, downloadCode, downloadStdout, downloadStderr)
		return "", err
	}

	//7.using winrm protocol to run install_adaegis.ps1
	installCmd := `powershell.exe -ExecutionPolicy Bypass -File "C:\install-adaegis.ps1"`

	// Execute installation script
	installStdout, installStderr, installCode, err := winrmClient.RunCmdWithContext(execCtx, installCmd)
	if err != nil || installCode != 0 {
		logger.Errorf("run install script err:%v, code:%d, stdout:%s, stderr:%s",
			err, installCode, installStdout, installStderr)
		return "", err
	}

	return installStdout, nil
}

func (s *ADAServiceV2) winRMUninstallSensor(ctx context.Context, dcIPs []string, adaServerIP, username, password string) (string, error) {
	dcIP := getValidDCServerIP(dcIPs)

	winrmClient, err := getWinRMClient(ctx, dcIP, username, password)
	if err != nil {
		logger.Errorf("get winrm client err:%v", err)
		return "", err
	}

	// update adaegis server address in uninstall-adaegis.ps1
	curDir, _ := os.Getwd()
	uninstallScriptFile := filepath.Join(curDir, "../download/sensor", "uninstall-adaegis.ps1")
	if _, err := os.Stat(uninstallScriptFile); err != nil {
		logger.Errorf("uninstall script(%s) not found, skip deploy sensor", uninstallScriptFile)
		return "", err
	}

	// Prepare download command for the installation script
	downloadCmd := fmt.Sprintf(`Invoke-WebRequest -Uri "http://%s/download/sensor/uninstall-adaegis.ps1" -OutFile "C:\uninstall-adaegis.ps1"`, adaServerIP)
	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	logger.Infof("winrm(dc ip:%s, username:%s) downloadCmd:%s", dcIP, username, downloadCmd)

	// Execute download command
	downloadStdout, downloadStderr, downloadCode, err := winrmClient.RunPSWithContext(execCtx, downloadCmd)
	if err != nil || downloadCode != 0 {
		logger.Errorf("run download script err:%v, code:%d, stdout:%s, stderr:%s",
			err, downloadCode, downloadStdout, downloadStderr)
		return "", err
	}

	//7.using winrm protocol to run install_adaegis.ps1
	installCmd := `powershell.exe -ExecutionPolicy Bypass -File "C:\uninstall-adaegis.ps1"`

	// Execute installation script
	installStdout, installStderr, installCode, err := winrmClient.RunCmdWithContext(execCtx, installCmd)
	if err != nil || installCode != 0 {
		logger.Errorf("run uninstall script err:%v, code:%d, stdout:%s, stderr:%s",
			err, installCode, installStdout, installStderr)
		return "", err
	}

	return installStdout, nil
}
