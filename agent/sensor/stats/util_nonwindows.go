//go:build !windows

package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"
	logger "github.com/sirupsen/logrus"
)

func GetNetDevices(ignoreLocalIface bool) (string, error) {
	ifaceMap := make(map[string]string)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	if len(ifaces) == 0 {
		return "", nil
	}

	for _, iface := range ifaces {
		var ips []string
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ignoreLocalIface && ipNet.IP.IsLoopback() {
				continue
			}
			if ipNet.IP.To4() == nil {
				continue
			}
			ips = append(ips, ipNet.IP.String())
		}
		if len(ips) == 0 {
			continue
		}
		ifaceMap[iface.Name] = strings.Join(ips, ",")
	}

	cardInfo, err := json.Marshal(&ifaceMap)
	if err != nil {
		return "", err
	}

	return string(cardInfo), nil
}

func getProcessCpuMemPercent(ctx context.Context, interval time.Duration, pid uint32) (float64, float64, error) {
	select {
	case <-ctx.Done():
		return 0, 0, ctx.Err()
	default:
	}

	p, err := process.NewProcess(int32(pid))
	if err != nil {
		logger.Errorf("get process info by pid:%d err:%v", pid, err)
		return 0, 0, err
	}

	if interval > 0 {
		timer := time.NewTimer(interval)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		case <-timer.C:
		}
	}

	cpuPercent, err := p.CPUPercent()
	if err != nil {
		return 0, 0, err
	}
	memPercent, err := p.MemoryPercent()
	if err != nil {
		return 0, 0, err
	}

	return cpuPercent, float64(memPercent), nil
}

func humanReadableBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func GetFQDNName() string {
	hostname, _ := os.Hostname()
	return hostname
}
