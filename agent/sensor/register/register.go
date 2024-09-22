package register

import (
	"ada/agent/sensor/common"
	"ada/agent/sensor/stats"
	"ada/infra/version"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	logger "github.com/sirupsen/logrus"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func Register(rdx *redis.Client, regCode string) error {
	ctx := context.Background()
	sensorId := uuid.NewString()

	var regMsg common.AdaMessage
	regMsg.TaskID = uuid.New().String()
	regMsg.AgentID = sensorId
	regMsg.Version = version.GetBuildVersion()
	regMsg.Timestamp = time.Now().Unix()
	regMsg.MsgType = common.T_CMD_SENSOR_REG
	regMsg.Data = make(map[string]string)
	regMsg.Data["reg_code"] = regCode
	regMsg.Data["sensor_id"] = sensorId
	regMsg.Data["version"] = regMsg.Version
	regMsg.Data["timestamp"] = strconv.FormatInt(regMsg.Timestamp, 10)
	regMsg.Data["ip"] = getLocalIP()

	domain, hostName, err := getHostDomain()
	if err != nil {
		logger.Errorf("get host domain err:%v", err)
		return err
	}
	regMsg.Data["domain"] = domain
	regMsg.Data["dc_hostname"] = hostName

	platform, _, platformVersion, err := host.PlatformInformation()
	if err != nil {
		logger.Errorf("get platform info err:%v", err)
		return err
	}

	regMsg.Data["platform"] = platform
	regMsg.Data["kernel_version"] = platformVersion

	cardInfo, err := stats.GetNetDevices()
	if err != nil {
		logger.Errorf("get net devices err:%v", err)
		return err
	}
	regMsg.Data["net_iface"] = cardInfo

	regMsg.Data["mem_total"] = ""
	memory, err := mem.VirtualMemory()
	if err == nil {
		regMsg.Data["mem_total"] = fmt.Sprintf("%d", memory.Total)
	}
	regMsg.Data["cpu_total"] = fmt.Sprintf("%d", runtime.NumCPU())

	regByte, err := json.Marshal(regMsg)
	if err != nil {
		return err
	}

	err = rdx.LPush(ctx, common.SensorStateQueue, regByte).Err()
	if err != nil {
		return err
	}

	taskSucc := false
	taskKey := fmt.Sprintf("%s_%s", common.SensorCmdRespKey, regMsg.TaskID)
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		succ := rdx.HGet(ctx, taskKey, "succeed").Val()
		if succ == "" {
			continue
		}
		if succ == "1" {
			// task succeed
			taskSucc = true
			break
		}
	}
	if taskSucc {
		return ioutil.WriteFile(filepath.Join(common.SensorDir, "uuid"), []byte(sensorId), 0644)
	}

	return fmt.Errorf("sensor register err or timeout")
}

// 获取域控DNSHostName名称
func getHostDomain() (string, string, error) {
	domain, hostname, err := getDomainByRegistry() // windows平台支持
	if err == nil {
		return domain, hostname, nil
	}

	cmd := exec.Command("wmic", []string{"computersystem", "get", "domain,DNSHostName"}...)
	bs, err := cmd.CombinedOutput()
	if err != nil {
		logger.Errorf("get domain err:%v", err)
		return "", "", err
	}

	lines := strings.SplitN(string(bs), "\n", 2)
	if len(lines) < 2 {
		logger.Errorf("string split err:%v", err)
		return "", "", fmt.Errorf("string split failed")
	}

	parts := strings.Fields(strings.TrimSpace(lines[1]))
	if len(parts) != 2 {
		hostname, err := os.Hostname()
		return hostname, "", err
	}

	return parts[0], parts[1], nil
}

func getLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}

	for _, addr := range addrs {
		ipAddr, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipAddr.IP.IsLoopback() {
			continue
		}
		if !ipAddr.IP.IsGlobalUnicast() {
			continue
		}
		return ipAddr.IP.String()
	}

	return ""
}
