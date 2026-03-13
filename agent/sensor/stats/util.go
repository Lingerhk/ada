//go:build windows

package stats

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/process"
	logger "github.com/sirupsen/logrus"

	"golang.org/x/sys/windows"
)

func GetNetDevices(ignoreLocalIface bool) (string, error) {
	ifaceMap := make(map[string]string)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return "", err
	}
	if len(devices) == 0 {
		return "", nil
	}

	for _, dev := range devices {
		var ips []string
		if len(dev.Addresses) > 0 {
			for _, address := range dev.Addresses {
				if ignoreLocalIface && address.IP.IsLoopback() {
					continue
				}

				if address.IP.To4() == nil {
					continue
				}
				ips = append(ips, address.IP.String())
			}
		}
		if len(ips) == 0 {
			continue
		}

		ifaceMap[dev.Name] = strings.Join(ips, ",")
	}

	cardInfo, err := json.Marshal(&ifaceMap)
	if err != nil {
		return "", err
	}

	return string(cardInfo), nil
}

// 根据pid获取进程CPU(单核利用率)/MEM信息
// 如果传入interval 则计算一段时间内的均值
// Add context for cancellation
func getProcessCpuMemPercent(ctx context.Context, interval time.Duration, pid uint32) (float64, float64, error) {
	// Check context immediately if interval is 0
	if interval <= 0 {
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
		// Use CPUPercentWithContext if possible (depends on gopsutil version, fallback otherwise)
		// Assuming standard CPUPercent for simplicity here, but context version is better.
		cpuPercent, _ := p.CPUPercent()
		memPercent, _ := p.MemoryPercent()

		return cpuPercent, float64(memPercent), nil
	}

	// For interval > 0, use a cancellable goroutine
	var hasErr error
	var cpuPercent float64
	var memPercent float64
	finish := make(chan bool)

	// Determine polling interval, ensure it's reasonable
	pollingInterval := interval / 60
	if pollingInterval < 100*time.Millisecond { // Avoid excessive polling
		pollingInterval = 100 * time.Millisecond
	}

	go func() {
		defer func() { finish <- true }() // Ensure finish is signaled
		var n float64
		ticker := time.NewTicker(pollingInterval)
		defer ticker.Stop()
		intervalTimeout := time.After(interval)

		for {
			select {
			case <-ctx.Done(): // Check for context cancellation
				hasErr = ctx.Err()
				return
			case <-intervalTimeout: // Check for interval timeout
				return // Interval completed normally
			case <-ticker.C: // Poll at ticker interval
				//执行轮询查询操作
				p, err := process.NewProcess(int32(pid))
				if err != nil {
					hasErr = fmt.Errorf("get process handle pid %d: %w", pid, err)
					return // Exit goroutine on process error
				}
				// Note: CPUPercent itself can block for a duration on first call or based on system load.
				// Using CPUPercentWithContext(ctx) would be ideal if available.
				curCpuPercent, err := p.CPUPercent()
				if err != nil {
					// Ignore CPU calculation error for this sample? Or return error?
					// Let's log and continue for now, maybe the next sample works.
					logger.Warnf("get cpu percent pid %d err: %v", pid, err)
					continue
				}
				curMem, err := p.MemoryPercent()
				if err != nil {
					logger.Warnf("get memory percent pid %d err: %v", pid, err)
					continue
				}

				n++
				//根据历史 统计均值
				cpuPercent = (cpuPercent*float64(n-1) + curCpuPercent) / n
				memPercent = (memPercent*float64(n-1) + float64(curMem)) / n
			}
		}
	}()

	// Wait for the goroutine to finish or be cancelled
	select {
	case <-ctx.Done():
		<-finish // Wait for goroutine cleanup if context cancelled first
		return 0, 0, ctx.Err()
	case <-finish:
		// Goroutine finished (normally or due to internal error/timeout)
		if hasErr != nil {
			// Return 0s and the specific error (could be context cancellation or process error)
			return 0, 0, hasErr
		}
		// Normal completion
		return cpuPercent, memPercent, nil
	}
}

// Add helper function for human-readable bytes
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

	// 1st call: get required buffer size
	var size uint32
	// COMPUTER_NAME_DNS_FULLY_QUALIFIED == 3
	err := windows.GetComputerNameEx(windows.ComputerNameDnsFullyQualified, nil, &size)
	if err != nil && err != windows.ERROR_MORE_DATA {
		logger.Errorf("get computer name ex err:%v", err)
		return hostname
	}

	// allocate buffer of UTF-16 words
	buf := make([]uint16, size)
	// 2nd call: actually fetch the name
	if err := windows.GetComputerNameEx(windows.ComputerNameDnsFullyQualified, &buf[0], &size); err != nil {
		logger.Errorf("get computer name ex err:%v", err)
		return hostname
	}

	return windows.UTF16ToString(buf[:size])
}
