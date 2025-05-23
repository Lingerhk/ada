package register

import (
	"ada/agent/sensor/common"
	"ada/agent/sensor/stats"
	"ada/infra/version"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/mem"
	logger "github.com/sirupsen/logrus"
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

	fqdn := stats.GetFQDNName()
	regMsg.Data["hostname"] = fqdn
	parts := strings.Split(fqdn, ".")
	if len(parts) > 1 {
		domain := strings.Join(parts[1:], ".")
		regMsg.Data["domain"] = domain
		regMsg.Data["dc_hostname"] = parts[0]
	} else {
		// If FQDN doesn't have domain parts, just use hostname
		hostname, _ := os.Hostname()
		regMsg.Data["domain"] = ""
		regMsg.Data["dc_hostname"] = hostname
	}

	platform, _, platformVersion, err := host.PlatformInformation()
	if err != nil {
		logger.Errorf("get platform info err:%v", err)
		return err
	}

	regMsg.Data["platform"] = platform
	regMsg.Data["kernel_version"] = platformVersion

	cardInfo, err := stats.GetNetDevices(true)
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
		return os.WriteFile(filepath.Join(common.SensorDir, "uuid"), []byte(sensorId), 0644)
	}

	return fmt.Errorf("sensor register err or timeout")
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
