package worker

import (
	"ada/backend/cache"
	"context"
	"fmt"
	"github.com/redis/go-redis/v9"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	logger "github.com/sirupsen/logrus"
	"strings"
	"time"
)

func (w *Worker) SystemSyncTask(ctx context.Context) error {
	w = w.withContext(ctx)
	// 1.采集系统状态
	saveStatsInfo(w.env.RedisCli)

	// 2.监控ES数据量，超标清除久数据(TODO: 在receiver中实现)

	return nil
}

func saveStatsInfo(redisCli *redis.Client) {
	ctx := context.Background()
	ts := time.Now().Unix()
	var infoMap = make(map[string]any)

	// 说明: Data节点(ES状态)在receiver模块完成(因为task_worker模块没有es cli)，并更新到ada:server:stats:info

	// delete old member first
	for _, statsKey := range []string{cache.SysStatsLoadKey, cache.SysStatsCpuKey, cache.SysStatsMemKey, cache.SysStatsNetTxKey, cache.SysStatsNetRxKey} {
		outLen := redisCli.LLen(ctx, statsKey).Val() - 60*24
		if outLen > 0 {
			redisCli.LTrim(ctx, statsKey, outLen, -1).Val()
		}
	}

	// get basic system info
	hostStat, err := host.Info()
	if err == nil {
		infoMap["hostname"] = hostStat.Hostname
		infoMap["uptime"] = hostStat.Uptime
		infoMap["platform"] = fmt.Sprintf("%s%s", hostStat.Platform, hostStat.PlatformVersion)
		infoMap["timestamp"] = time.Now().Unix() // 通过此字段判断agent存活状态
	}

	diskStat, err := disk.Usage("/")
	if err == nil {
		infoMap["disk_total"] = fmt.Sprintf("%dGB", diskStat.Total/1024/1024/1024)
		infoMap["disk_percent"] = fmt.Sprintf("%.2f", diskStat.UsedPercent)
	}
	physicalCnt, err := cpu.Counts(false)
	if err == nil {
		infoMap["cpu_cores"] = fmt.Sprintf("%d", physicalCnt)
	}

	loadStat, err := load.Avg()
	if err == nil {
		infoMap["local_15m"] = fmt.Sprintf("%.2f", loadStat.Load15)

		statsVal := fmt.Sprintf("%d:%.2f", ts, loadStat.Load1)
		err = redisCli.RPush(ctx, cache.SysStatsLoadKey, statsVal).Err()
		if err != nil {
			logger.Warnf("redis save stats_load err:%v", err)
		}
	}

	cpuUsed, err := cpu.Percent(2*time.Second, false)
	if err == nil {
		infoMap["cpu_percent"] = fmt.Sprintf("%.2f", cpuUsed[0])

		statsVal := fmt.Sprintf("%d:%.2f", ts, cpuUsed[0])
		err = redisCli.RPush(ctx, cache.SysStatsCpuKey, statsVal).Err()
		if err != nil {
			logger.Warnf("redis save stats_cpu err:%v", err)
		}
	}

	vmStat, err := mem.VirtualMemory()
	if err == nil {
		infoMap["mem_total"] = fmt.Sprintf("%dGB", vmStat.Total/1024/1024/1024)
		infoMap["mem_percent"] = fmt.Sprintf("%.2f", vmStat.UsedPercent)

		statsVal := fmt.Sprintf("%d:%.2f", ts, vmStat.UsedPercent)
		err = redisCli.RPush(ctx, cache.SysStatsMemKey, statsVal).Err()
		if err != nil {
			logger.Warnf("redis save stats_mem err:%v", err)
		}
	}

	// 读取所有网卡网速
	invalidNics := []string{"lo", "tun", "tap", "br", "veth", "docker"}
	Net, err := net.IOCounters(true)
	if nil != err {
		return
	}

	var rx, tx uint64
	for _, nv := range Net {
		validNic := true
		for _, nic := range invalidNics {
			if strings.Contains(nv.Name, nic) {
				validNic = false
				continue
			}
		}
		if validNic {
			rx += nv.BytesRecv
			tx += nv.BytesSent
		}
	}

	time.Sleep(2 * time.Second)

	// 重新读取网络信息
	Net, err = net.IOCounters(true)
	if nil != err {
		return
	}

	var rx2, tx2 uint64
	for _, nv := range Net {
		validNic := true
		for _, nic := range invalidNics {
			if strings.Contains(nv.Name, nic) {
				validNic = false
				break
			}
		}
		if validNic {
			rx2 += nv.BytesRecv
			tx2 += nv.BytesSent
		}
	}

	rxSpeed := (rx2 - rx) * 8 / (1024 * 2) // Kb/s
	txSpeed := (tx2 - tx) * 8 / (1024 * 2) // Kb/s

	statsVal := fmt.Sprintf("%d:%d", ts, rxSpeed)
	err = redisCli.RPush(ctx, cache.SysStatsNetRxKey, statsVal).Err()
	if err != nil {
		logger.Warnf("redis save stats_net_rx err:%v", err)
	}

	statsVal = fmt.Sprintf("%d:%d", ts, txSpeed)
	err = redisCli.RPush(ctx, cache.SysStatsNetTxKey, statsVal).Err()
	if err != nil {
		logger.Warnf("redis save stats_net_tx err:%v", err)
	}

	err = redisCli.HMSet(ctx, cache.SysStatsInfoKey, infoMap).Err()
	if err != nil {
		logger.Warnf("redis save stats_info err:%v", err)
	}
}
