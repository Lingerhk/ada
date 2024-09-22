package stats

import (
	"ada/agent/sensor/common"
	"encoding/json"
	"github.com/go-cmd/cmd"
	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/process"
	"github.com/sirupsen/logrus"
	"path/filepath"
	"strings"
	"time"
)

func getNetIface() (map[string]string, error) {
	ifaceMap := make(map[string]string)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return ifaceMap, nil
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

	return ifaceMap, nil
}

func getNtapIfaceList() (map[string]string, error) {
	ntapBin := filepath.Join(common.SensorDir, "ntap", common.PlugNtapProcName)
	ntapProc := cmd.NewCmd(ntapBin)
	ntapProc.Args = []string{"/c"}
	status := <-ntapProc.Start()

	var firstLine bool
	ifaceIdxMap := make(map[string]string)
	for _, line := range status.Stdout {
		if strings.HasPrefix(line, "Available interfaces:") {
			firstLine = true
			continue
		}
		if firstLine && strings.Contains(line, "[index=") {
			parts := strings.Fields(line)
			IdxDesc := strings.SplitN(parts[0], "[index=", 2)
			idxNum := string(IdxDesc[1][0])
			devName := parts[1]
			ifaceIdxMap[idxNum] = devName[1 : len(devName)-1]
		}
	}

	return ifaceIdxMap, nil
}

func GetNetDevices() (string, error) {
	ifaceMap, err := getNetIface()
	if err != nil {
		return "", err
	}

	ifaceIdxMap, err := getNtapIfaceList()
	if err != nil {
		return "", err
	}

	var cardMap = make(map[string]string)
	for devName, ips := range ifaceMap {
		for idNum, ifaceName := range ifaceIdxMap {
			if ifaceName == devName {
				cardMap[idNum] = ips
				break
			}
		}
	}

	cardInfo, err := json.Marshal(&cardMap)
	if err != nil {
		return "", err
	}

	return string(cardInfo), nil
}

// 获取的驱动列表
//func GetNetDevices() (string, error) {
//	// 多次尝试获取，失败重试
//	cardIPMap := map[string]string{}
//	for i := 0; i < 5; i++ {
//		devices, err := pcap.FindAllDevs()
//		if err != nil {
//			return "", err
//		}
//		if len(devices) == 0 {
//			time.Sleep(2 * time.Second)
//			continue
//		}
//
//		var idx = 0
//		for _, dev := range devices {
//			name := dev.Name
//			var ips string
//			if len(dev.Addresses) > 0 {
//				ips = ""
//				for i, address := range dev.Addresses {
//					if i > 0 {
//						ips += " "
//					}
//					ips += fmt.Sprintf("%s", address.IP.String())
//				}
//				name += fmt.Sprintf(" (%s)", ips)
//			}
//			cardIPMap[strconv.Itoa(idx)] = name
//			idx++
//		}
//		break
//	}
//
//	cardInfo, err := json.Marshal(&cardIPMap)
//	if err != nil {
//		return "", err
//	}
//
//	return string(cardInfo), nil
//}

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
