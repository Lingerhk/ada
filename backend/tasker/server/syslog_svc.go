package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"ada/backend/cache"
	"ada/backend/recevier/pktlog"
	"ada/backend/tasker/config"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	logger "github.com/sirupsen/logrus"
	"gopkg.in/mcuadros/go-syslog.v2"
)

const (
	eveLogQueueKey    = "ada:evelog_queue" // same with receiver module
	eveLogIndexPrefix = "ada-eventlog"
)

const mapping = `{
	"settings": {
	  "number_of_shards": 1,
	  "number_of_replicas": 0
	},
	"mappings": {
	  "properties": {
		"@timestamp": {
		  "type": "date"
		}
	  }
	}
  }`

type nodeStats struct {
	DiskAvail       string `json:"diskAvail"`
	DiskUsedPercent string `json:"diskUsedPercent"`
	DiskTotal       string `json:"diskTotal"`
	RamPercent      string `json:"ramPercent"`
	RamTotal        string `json:"ramMax"`
	CpuPercent      string `json:"cpu"`
	SysLoad1m       string `json:"load_1m"`
}

type nodeHealth struct {
	Epoch               string `json:"epoch"`
	Timestamp           string `json:"timestamp"`
	Cluster             string `json:"cluster"`
	Status              string `json:"status"`
	NodeTotal           string `json:"node.total"`
	NodeData            string `json:"node.data"`
	Shards              string `json:"shards"`
	Pri                 string `json:"pri"`
	Relo                string `json:"relo"`
	Init                string `json:"init"`
	Unassign            string `json:"unassign"`
	PendingTasks        string `json:"pending_tasks"`
	MaxTaskWaitTime     string `json:"max_task_wait_time"`
	ActiveShardsPercent string `json:"active_shards_percent"`
}

type indexStats struct {
	Health       string `json:"health"`
	Status       string `json:"status"`
	Index        string `json:"index"`
	Uuid         string `json:"uuid"`
	Pri          string `json:"pri"`
	Rep          string `json:"rep"`
	DocsCount    string `json:"docs.count"`
	DocsDeleted  string `json:"docs.deleted"`
	StoreSize    string `json:"store.size"`
	PriStoreSize string `json:"pri.store.size"`
	DatasetSize  string `json:"dataset.size"`
}

type SyslogServer struct {
	ctx           context.Context
	env           *config.Env
	esBulker      esutil.BulkIndexer
	channel       syslog.LogPartsChannel
	server        *syslog.Server
	dcHostnameMap map[string]string // cache mapping dcHostname&ip 减少redis查询
	currIndexMap  map[string]bool   // 当创建es index后缓存在此，避免每次写入前判断index是否存在
	stop          bool
}

func NewSyslogServer(env *config.Env) (*SyslogServer, error) {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC3164) // BSD syslog (RFC 3164) | IETF Syslog (RFC 5424)
	server.SetHandler(handler)
	err := server.ListenUDP(env.Cfg.TaskSrv.SyslogAddr)
	if err != nil {
		logger.Errorf("listen udp err:%v", err)
		return nil, err
	}

	logger.Infof("Listening on %s for syslog", env.Cfg.TaskSrv.SyslogAddr)

	// init es bulk indexer
	var bi esutil.BulkIndexer
	if env.Cfg.ES.Enable {
		bi, err = esutil.NewBulkIndexer(esutil.BulkIndexerConfig{
			Client:        env.EsCli,
			FlushInterval: 5 * time.Second,
		})
		if err != nil {
			logger.Errorf("init es bulk indexer err:%v", err)
			return nil, err
		}
	}

	dcHostnameMap := make(map[string]string)
	currIndexMap := make(map[string]bool)

	return &SyslogServer{esBulker: bi, channel: channel, server: server, dcHostnameMap: dcHostnameMap, currIndexMap: currIndexMap}, nil
}

func (s *SyslogServer) SyslogServe() {
	s.server.Boot()

	// 启动es indices状态监控(stats, delete old data)
	if s.env.Cfg.ES.Enable {
		go s.monitor()
	}

	go func(channel syslog.LogPartsChannel) {
		for logParts := range s.channel {
			go s.sync(logParts)
		}
	}(s.channel)

	s.server.Wait()
}

func (s *SyslogServer) Stop() {
	s.stop = true
	s.server.Kill()
	s.esBulker.Close(context.Background())
}

func (s *SyslogServer) sync(event map[string]interface{}) {
	// "client":"192.168.145.135:49627",
	// "facility":1,
	// "hostname":"DC2019-02.china.com",
	// "priority":14,
	// "severity":6,
	// "tag":"Microsoft-Windows-Security-Auditing",
	// "timestamp":time.Date(2023, time.December, 31, 14, 43, 49, 0, time.UTC),

	logger.Debugf("recv syslog:%#v", event)

	ctx := context.Background()

	hostname := event["hostname"].(string)
	client := event["client"].(string)

	c := strings.SplitN(client, ":", 2) // c[0]: client_ip, c[1]: client_port
	if len(c) != 2 {
		logger.Errorf("parser client %s to ip failed", client)
		return
	}

	parts := strings.SplitN(hostname, ".", 2) // parts[0]: DC, parts[1]: domainName
	if len(parts) != 2 {
		logger.Errorf("ignore invalid syslog from hostname(%s):%s", client, hostname)
		return
	}

	rdxDomainKey := cache.DomainIPRelateDCKey(parts[1])
	if s.env.RedisCli.Exists(ctx, rdxDomainKey).Val() == 0 {
		logger.Warnf("ignore invalid syslog from hostname:%s, please add domain first!", hostname)
		return
	}
	// update the mapping hostname&client into redis cache
	if ip, ok := s.dcHostnameMap[hostname]; !ok || ip != c[0] {
		// 设置为通用KV形式，便于zeek-redis模块直接从redis中根据ip获取dc hostname
		rdxDcIPKey := cache.DomainIPRelateDCNameKey(c[0])
		if err := s.env.RedisCli.Set(ctx, rdxDcIPKey, hostname, 0).Err(); err != nil {
			logger.Errorf("update domain cache to redis err%v", err)
			return
		}
		s.dcHostnameMap[hostname] = c[0]
	}

	// 记录当前dc的timestamp到SensorCollectStatusKey中，task_worker会check是否异常
	ts := time.Now().Unix()
	if ts%10 == 0 {
		_ = s.env.RedisCli.HSet(ctx, cache.SensorCollectStatusKey, "rawlog_"+hostname, ts).Err()
	}

	// 如果queue超过20W条，则清除5%旧数据。每个eventlog按4KB计算，4KB*200000 = 780MB
	if s.env.RedisCli.LLen(ctx, eveLogQueueKey).Val() > 200000 {
		logger.Warnf("queue %s is full, will remove some old eventlog", eveLogQueueKey)
		s.env.RedisCli.LTrim(ctx, eveLogQueueKey, 1000, -1)
	}

	content := event["content"].(string)
	if err := s.env.RedisCli.LPush(ctx, eveLogQueueKey, content).Err(); err != nil {
		logger.Errorf("lpush redis err:%v", err)
		// do nothing
	}

	if !s.env.Cfg.ES.Enable {
		return
	}

	indexName := fmt.Sprintf("%s-%s", eveLogIndexPrefix, time.Now().Format("2006.01.02"))

	if _, ok := s.currIndexMap[indexName]; !ok {
		// check if the index is created. if not, create first.
		req := esapi.IndicesExistsRequest{Index: []string{indexName}}
		r, err := req.Do(context.Background(), s.env.EsCli)
		if err != nil {
			logger.Errorf("request es exist index err:%v", err)
			return
		}
		defer r.Body.Close()

		// is index doesn't exist, the status_code is 404
		if r.StatusCode == 404 {
			// create index
			req := esapi.IndicesCreateRequest{
				Index: indexName,
				Body:  strings.NewReader(mapping),
			}
			res, err := req.Do(context.Background(), s.env.EsCli)
			if err != nil {
				logger.Errorf("request es create err:%v", err)
				return
			}
			defer res.Body.Close()
		}

		s.currIndexMap[indexName] = true // 更新cache
	}

	item := esutil.BulkIndexerItem{
		Action: "index",
		Index:  indexName,
		Body:   strings.NewReader(content),
		// OnFailure is the optional callback for each failed operation
		OnFailure: func(
			ctx context.Context,
			item esutil.BulkIndexerItem,
			res esutil.BulkIndexerResponseItem, err error,
		) {
			if err != nil {
				logger.Warnf("bulk indexer item on-failure err:%v", err)
			}
		},
	}
	err := s.esBulker.Add(ctx, item)
	if err != nil {
		logger.Errorf("bulk indexing document err:%v", err)
		return
	}

	logger.Debugf("sotred syslog(hostname:%s) into es succed", hostname)
}

func (s *SyslogServer) monitor() {
	var last int64

	for {
		if s.stop {
			break
		}

		time.Sleep(1 * time.Second)
		now := time.Now().Unix()
		if now-last > 300 {
			s.stats()
			last = now
		}
	}
}

func (s *SyslogServer) stats() {
	ctx := context.Background()
	var infoMap = make(map[string]interface{})
	infoMap["es_check_tm"] = strconv.FormatInt(time.Now().Unix(), 10)

	// GET /_cat/health?v=true&format=json
	req := esapi.CatHealthRequest{Format: "json"}
	res, err := req.Do(ctx, s.env.EsCli)
	if err != nil {
		logger.Errorf("Error getting response: %v", err)
		infoMap["es_check_stats"] = "red"
		_ = s.env.RedisCli.HMSet(ctx, cache.SysStatsInfoKey, infoMap).Err()
		return
	}
	defer res.Body.Close()
	if res.IsError() {
		logger.Errorf("[%s] Error health es node", res.Status())
		return
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Errorf("read response body err: %v", err)
		return
	}

	var healths []nodeHealth
	if err = json.Unmarshal(b, &healths); err != nil {
		logger.Errorf("json unmarshal response body err: %v", err)
		return
	}
	if len(healths) <= 0 {
		logger.Error("empty es node stats in resp")
		return
	}

	infoMap["es_check_stats"] = healths[0].Status
	infoMap["es_active_shards"] = healths[0].ActiveShardsPercent

	// curl -u"elastic:nX0ZIN0AIfFs5x=fZfuE" -XGET 'localhost:9200/_cat/nodes?format=json&h=diskAvail,diskTotal,diskUsedPercent,ramPercent,cpu,load_1m,ramCurrent,ramMax'
	req2 := esapi.CatNodesRequest{Format: "json", H: []string{"diskAvail", "diskUsedPercent", "diskTotal", "ramPercent", "ramMax", "cpu", "load_1m"}}
	res2, err := req2.Do(ctx, s.env.EsCli)
	if err != nil {
		logger.Errorf("Error getting response: %v", err)
		return
	}
	defer res2.Body.Close()
	if res2.IsError() {
		logger.Errorf("[%s] Error stats es node", res2.Status())
		return
	}

	b, err = io.ReadAll(res2.Body)
	if err != nil {
		logger.Errorf("read response body err: %v", err)
		return
	}

	var stats []nodeStats
	if err = json.Unmarshal(b, &stats); err != nil {
		logger.Errorf("json unmarshal response body err: %v", err)
		return
	}
	if len(stats) <= 0 {
		logger.Error("empty es node stats in resp")
		return
	}

	// 当磁盘空间不足时，进行旧数据删除
	diskUsed, err := strconv.ParseFloat(stats[0].DiskUsedPercent, 32)
	if err == nil {
		// get the diskUsedPercent threshold from redis
		diskUsedThresholdStr := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "es_disk_percent_delete").Val()
		var threshold = 85.0
		if diskUsedThresholdStr != "" {
			thresholdVal, err := strconv.ParseFloat(diskUsedThresholdStr, 32)
			if err == nil {
				if thresholdVal > 90.0 {
					threshold = 90.0
				} else if thresholdVal < 30.0 {
					threshold = 30.0
				} else {
					threshold = thresholdVal
				}
			}
		}

		if diskUsed > threshold {
			logger.Infof("ES related Disk Used up to %2.f, will try delete the oldest index release disk", diskUsed)
			s.deleteOldestIndex(ctx)
		}
	} else {
		logger.Errorf("covert diskUsedPercent to float32 err:%v", stats[0].DiskUsedPercent)
	}

	// 将ES状态信息更新到redis
	infoMap["es_disk_total"] = stats[0].DiskTotal
	infoMap["es_disk_avail"] = stats[0].DiskAvail
	infoMap["es_disk_percent"] = stats[0].DiskUsedPercent
	infoMap["es_mem_percent"] = stats[0].RamPercent
	infoMap["es_mem_total"] = stats[0].RamTotal
	infoMap["es_cpu_percent"] = stats[0].CpuPercent
	infoMap["es_sys_load1m"] = stats[0].SysLoad1m
	err = s.env.RedisCli.HMSet(ctx, cache.SysStatsInfoKey, infoMap).Err()
	if err != nil {
		logger.Warnf("redis save stats_info err:%v", err)
	}
}

func (s *SyslogServer) deleteOldestIndex(ctx context.Context) {
	// TODO: bug fix: 下面结果返回的list中的顺序是 eveLogIndexPrefix，再PktLogIndexPrefix
	// 需要按日志删除日志。todo： 比较两个日志中时间最早的，进行删除。
	req := esapi.CatIndicesRequest{
		Format: "json",
		Index:  []string{eveLogIndexPrefix + "-*", pktlog.PktLogIndexPrefix + "-*"},
		S:      []string{"index"},
	}
	res, err := req.Do(ctx, s.env.EsCli)
	if err != nil {
		logger.Errorf("Error cat_indices req: %v", err)
		return
	}
	defer res.Body.Close()
	if res.IsError() {
		logger.Errorf("[%s] Error cat_indices", res.Status())
		return
	}

	b, err := io.ReadAll(res.Body)
	if err != nil {
		logger.Errorf("read response body err: %v", err)
		return
	}

	var indices []indexStats
	if err = json.Unmarshal(b, &indices); err != nil {
		logger.Errorf("json unmarshal response body err: %v", err)
		return
	}
	if len(indices) <= 0 {
		return
	}

	req2 := esapi.IndicesDeleteRequest{
		Index: []string{indices[0].Index},
	}
	res2, err := req2.Do(ctx, s.env.EsCli)
	if err != nil {
		logger.Errorf("Error delete index(%s) req: %v", indices[0].Index, err)
		return
	}
	defer res2.Body.Close()
	if res2.IsError() {
		logger.Errorf("[%s] Error delete index", res.Status())
		return
	}

	logger.Infof("deleted the oldest index: %s, dataset.size:%s", indices[0].Index, indices[0].DatasetSize)
}
