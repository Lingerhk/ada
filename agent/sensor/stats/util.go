package stats

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"
)

func GetNetDevices() (string, error) {
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
func getProcessCpuMemPercent(interval time.Duration, pid uint32) (float64, float32, error) {
	if interval <= 0 {
		p, err := process.NewProcess(int32(pid))
		if err != nil {
			logrus.Errorf("get process info by pid:%d err:%v", pid, err)
			return 0, 0, err
		}
		cpuPercent, _ := p.CPUPercent()
		memPercent, _ := p.MemoryPercent()

		return cpuPercent, memPercent, nil
	}

	var hasErr error
	var cpuPercent float64
	var memPercent float32
	timeout := time.After(interval)
	finish := make(chan bool)
	go func() {
		var n float32
		for {
			select {
			case <-timeout:
				finish <- true
				return
			default:
				//执行轮询查询操作
				p, err := process.NewProcess(int32(pid))
				if err != nil {
					hasErr = err
					return
				}
				curCpuPercent, err := p.CPUPercent()
				if err != nil {
					hasErr = err
					return
				}
				curMem, err := p.MemoryPercent()
				if err != nil {
					hasErr = err
					return
				}

				n++
				//根据历史 统计均值
				cpuPercent = (cpuPercent*float64(n-1) + curCpuPercent) / float64(n)
				memPercent = (memPercent*(n-1) + curMem) / n
			}
			time.Sleep(interval / 60)
		}
	}()
	<-finish

	if hasErr != nil {
		return 0, 0, hasErr
	}

	return cpuPercent, memPercent, nil
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
