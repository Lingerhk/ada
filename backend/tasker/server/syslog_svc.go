package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"ada/backend/cache"
	"ada/backend/tasker/config"
	"ada/infra/base"

	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/elastic/go-elasticsearch/v8/esutil"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"gopkg.in/mcuadros/go-syslog.v2"
)

const (
	maxLogQueueLen    = 1024 * 512         // 日志队列的最大长度(velog&pktlog), 实试20W条evelog约250M
	eveLogQueueKey    = "ada:evelog_queue" // same with engine module
	pktLogQueueKey    = "ada:pktlog_queue" // same with engine module
	eveLogIndexPrefix = "ada-eventlog"
	pktLogIndexPrefix = "ada-packetlog"
	pktLogChannel     = "ada:pktlog_channel" // receive pktlog from zeek-redis
	statsListMaxLen   = 60 * 24 * 7          // Max length for stats lists (7 days of minutely data)
)

const (
	eveLogMapping = `{
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

	pktLogMapping = `{
	"settings": {
	  "number_of_shards": 1,
	  "number_of_replicas": 0
	},
	"mappings": {
	  "properties": {
		"ts": {
		  "type": "date"
		}
	  }
	}
  }`
)

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
	env             *config.Env
	ctx             context.Context
	cancel          context.CancelFunc
	esBulker        esutil.BulkIndexer
	channel         syslog.LogPartsChannel
	server          *syslog.Server
	dcHostnameMap   map[string]string // cache mapping dcHostname&ip 减少redis查询
	eveLogIndexName string            // 当前evelog日志index的日期,用于缓存
	pktLogIndexName string            // 当前pktlog日志index的日期,用于缓存
	logStats        *sync.Map         // map[domain]count - Added for pktlog stats
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
	ctx, cancel := context.WithCancel(context.Background())

	return &SyslogServer{
		ctx:           ctx,
		env:           env,
		cancel:        cancel,
		esBulker:      bi,
		channel:       channel,
		server:        server,
		dcHostnameMap: dcHostnameMap,
		logStats:      new(sync.Map), // Initialize the map
	}, nil
}

func (s *SyslogServer) SyslogServe() {
	s.server.Boot()

	// 启动es indices状态监控(stats, delete old data)
	if s.env.Cfg.ES.Enable {
		go s.monitor()
	}

	go func(channel syslog.LogPartsChannel) {
		for logParts := range s.channel {
			go s.syslogSync(logParts)
		}
	}(s.channel)

	s.server.Wait()
}

func (s *SyslogServer) Stop() {
	s.server.Kill()
	s.cancel()
	s.esBulker.Close(s.ctx)
}

func (s *SyslogServer) syslogSync(event map[string]interface{}) {
	// "client":"192.168.145.135:49627",
	// "facility":1,
	// "hostname":"DC2019-02.china.com",
	// "priority":14,
	// "severity":6,
	// "tag":"Microsoft-Windows-Security-Auditing",
	// "timestamp":time.Date(2023, time.December, 31, 14, 43, 49, 0, time.UTC),

	logger.Debugf("recv syslog:%#v", event)

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
	if s.env.RedisCli.Exists(s.ctx, rdxDomainKey).Val() == 0 {
		logger.Warnf("ignore invalid syslog from hostname:%s, please add domain first!", hostname)
		return
	}
	// update the mapping hostname&client into redis cache
	if ip, ok := s.dcHostnameMap[hostname]; !ok || ip != c[0] {
		// 设置为通用KV形式，便于zeek-redis模块直接从redis中根据ip获取dc hostname
		rdxDcIPKey := cache.DomainIPRelateDCNameKey(c[0])
		if err := s.env.RedisCli.Set(s.ctx, rdxDcIPKey, hostname, 0).Err(); err != nil {
			logger.Errorf("update domain cache to redis err%v", err)
			return
		}
		s.dcHostnameMap[hostname] = c[0]
	}

	// 记录当前dc的timestamp到SensorCollectStatusKey中，task_worker会check是否异常
	now := time.Now()
	if now.Unix()%4 == 0 {
		_ = s.env.RedisCli.HSet(s.ctx, cache.SensorCollectStatusKey, "winlog_"+hostname, now.Unix()).Err()

		// 如果queue超过52.4W条（约650M），则清除部分旧数据。实测20W条约占redis内存：250M
		if s.env.RedisCli.LLen(s.ctx, eveLogQueueKey).Val() > maxLogQueueLen {
			logger.Warnf("queue %s is full, will remove some old eventlog", eveLogQueueKey)
			s.env.RedisCli.LTrim(s.ctx, eveLogQueueKey, 1024*10, -1)
		}
	}

	content := event["content"].(string)
	if err := s.env.RedisCli.LPush(s.ctx, eveLogQueueKey, content).Err(); err != nil {
		logger.Errorf("lpush redis err:%v", err)
		// do nothing
	}

	// 记录stats
	err := s.collectLogStats("winlog", hostname, now)
	if err != nil {
		logger.Warnf("collect evelog stats err:%v", err)
	}

	if !s.env.Cfg.ES.Enable {
		return
	}

	s.checkIndex(eveLogIndexPrefix)

	item := esutil.BulkIndexerItem{
		Action: "index",
		Index:  s.eveLogIndexName,
		Body:   strings.NewReader(content),
		// OnFailure is the optional callback for each failed operation
		OnFailure: func(
			ctx context.Context,
			item esutil.BulkIndexerItem,
			res esutil.BulkIndexerResponseItem, err error,
		) {
			if err != nil {
				logger.Warnf("bulk indexer item(evelog) on-failure err:%v", err)
			}
		},
	}
	err = s.esBulker.Add(s.ctx, item)
	if err != nil {
		logger.Errorf("bulk indexing document err:%v", err)
		return
	}

	logger.Debugf("sotred syslog(hostname:%s) into es succed", hostname)
}

func (s *SyslogServer) monitor() {
	var last int64

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			time.Sleep(1 * time.Second)
			now := time.Now().Unix()
			if now-last > 300 {
				s.stats()
				last = now
			}
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
	// TODO: bug fix: 下面结果返回的list中的顺序是 eveLogIndexPrefix，再pktLogIndexPrefix
	// 需要按日志删除日志。todo： 比较两个日志中时间最早的，进行删除。
	req := esapi.CatIndicesRequest{
		Format: "json",
		Index:  []string{eveLogIndexPrefix + "-*", pktLogIndexPrefix + "-*"},
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

// for pktlog
func (s *SyslogServer) PktlogServe() {
	pubsub := s.env.RedisCli.PSubscribe(s.ctx, pktLogChannel)
	defer pubsub.Close()

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			msg, err := pubsub.ReceiveTimeout(s.ctx, 5*time.Second)
			if err != nil {
				if err := pubsub.Ping(s.ctx); err != nil {
					logger.Errorf("PubSub failure:%s", err.Error())
				}
				time.Sleep(2 * time.Second)
				continue
			}
			switch msg := msg.(type) {
			case *redis.Message:
				logger.Infof("channel: %s received: %s", msg.Channel, msg.Payload)
				go s.pktlogSync(s.ctx, msg.Payload)
			}
		}
	}
}

func (s *SyslogServer) pktlogSync(ctx context.Context, event string) {
	// event format: hostname::pktlog_json
	pktlog := strings.SplitN(event, "::{", 2)
	if len(pktlog) != 2 {
		logger.Warnf("invalid pktlog event: %s", event)
		return
	}

	// 如果queue超过52.4W条（约200M），则清除部分旧数据。
	now := time.Now()
	if now.Unix()%4 == 0 {
		_ = s.env.RedisCli.HSet(s.ctx, cache.SensorCollectStatusKey, "pktlog_"+pktlog[0], now.Unix()).Err()

		if s.env.RedisCli.LLen(ctx, pktLogQueueKey).Val() > maxLogQueueLen {
			logger.Warnf("queue %s is full, will remove some old packetlog", pktLogQueueKey)
			s.env.RedisCli.LTrim(ctx, pktLogQueueKey, 1024*10, -1)
		}
	}

	// --- Start pktlog stats logic ---
	err := s.collectLogStats("pktlog", pktlog[0], now)
	if err != nil {
		logger.Warnf("collect pktlog stats err:%v", err)
	}

	if !s.env.Cfg.ES.Enable {
		return
	}

	s.checkIndex(pktLogIndexPrefix)

	item := esutil.BulkIndexerItem{
		Action: "index",
		Index:  s.pktLogIndexName,
		Body:   strings.NewReader(pktlog[1]),
		// OnFailure is the optional callback for each failed operation
		OnFailure: func(
			ctx context.Context,
			item esutil.BulkIndexerItem,
			res esutil.BulkIndexerResponseItem, err error,
		) {
			if err != nil {
				logger.Warnf("bulk indexer item(pktlog) on-failure err:%v", err)
			}
		},
	}
	err = s.esBulker.Add(s.ctx, item)
	if err != nil {
		logger.Errorf("bulk indexing document err:%v", err)
		return
	}

	logger.Debug("sotred pktlog into es succed")
}

func (s *SyslogServer) collectLogStats(logType string, hostname string, now time.Time) error {
	// design a redis structure to store the stats info of ada:server:stats:pktlog:%s, count the logs every minute, and save the result to redis
	// use zset to store the stats info, max count 60 *24 *7 days
	// in apiserver, get the stats info by domain and send to frontend to show the line chart

	var statsKey string

	domain := strings.ToLower(base.GetDomainFromHostname(hostname))

	switch logType {
	case "winlog":
		statsKey = fmt.Sprintf(cache.SysStatsWinLogKey, domain)
	case "pktlog":
		statsKey = fmt.Sprintf(cache.SysStatsPktLogKey, domain)
	default:
		return fmt.Errorf("invalid log type: %s", logType)
	}

	// get the current minute
	minuteTs := now.Truncate(time.Minute).Unix()
	statsCacheKey := fmt.Sprintf("%s:%d", statsKey, minuteTs)

	// count the logs in the current minute
	counts, exist := s.logStats.LoadOrStore(statsCacheKey, int64(1))
	if exist {
		if currentCount, ok := counts.(int64); ok {
			s.logStats.Store(statsCacheKey, currentCount+1)
		} else {
			logger.Errorf("Type assertion failed for counts in statsCacheKey: %s. Expected int64, got %T", statsCacheKey, counts)
			s.logStats.Store(statsCacheKey, int64(1))
		}
	} else {
		// if the stats info not exist, it means a new stats cycle, save the old stats info to redis and delete it
		oldMinuteTs := minuteTs - 60
		oldStatsCacheKey := fmt.Sprintf("%s:%d", statsKey, oldMinuteTs)
		oldCountsAny, exist := s.logStats.Load(oldStatsCacheKey)
		if exist {
			if oldCounts, ok := oldCountsAny.(int64); ok {
				oldCountsStr := strconv.FormatInt(oldCounts, 10)
				s.env.RedisCli.ZAdd(s.ctx, statsKey, redis.Z{Score: float64(oldMinuteTs), Member: oldCountsStr})
				s.logStats.Delete(oldStatsCacheKey)

				// Trim the ZSet if it exceeds the maximum length
				count, err := s.env.RedisCli.ZCard(s.ctx, statsKey).Result()
				if err == nil && count > statsListMaxLen {
					// Remove the oldest entries beyond the max length
					// ZREMRANGEBYRANK removes elements in the range [start, stop]
					// To keep the newest 'statsListMaxLen' items, we remove from index 0 up to 'count - statsListMaxLen - 1'
					remCount := count - statsListMaxLen
					if remCount > 0 {
						s.env.RedisCli.ZRemRangeByRank(s.ctx, statsKey, 0, remCount-1)
					}
				}
			} else {
				logger.Errorf("Type assertion failed for oldCounts in statsCacheKey: %s. Expected int64, got %T", oldStatsCacheKey, oldCountsAny)
				s.logStats.Delete(oldStatsCacheKey)
			}
		}
	}

	return nil
}

func (s *SyslogServer) checkIndex(logIndexPrefix string) {
	var oldLogIndexname, logIndexMapping string
	if logIndexPrefix == eveLogIndexPrefix {
		oldLogIndexname = s.eveLogIndexName
		logIndexMapping = eveLogMapping
	} else if logIndexPrefix == pktLogIndexPrefix {
		oldLogIndexname = s.pktLogIndexName
		logIndexMapping = pktLogMapping
	}

	currentIndexName := fmt.Sprintf("%s-%s", logIndexPrefix, time.Now().Format("2006.01.02"))
	if currentIndexName == oldLogIndexname {
		return
	}

	// check if the index is created. if not, create first.
	req := esapi.IndicesExistsRequest{Index: []string{currentIndexName}}
	r, err := req.Do(context.Background(), s.env.EsCli)
	if err != nil {
		logger.Errorf("request es exist index(%s) err:%v", currentIndexName, err)
		return
	}
	defer r.Body.Close()

	if r.StatusCode == 404 {
		req := esapi.IndicesCreateRequest{
			Index: currentIndexName,
			Body:  strings.NewReader(logIndexMapping),
		}
		res, err := req.Do(s.ctx, s.env.EsCli)
		if err != nil {
			logger.Errorf("request es create err:%v", err)
			return
		}
		defer res.Body.Close()
	}

	if logIndexPrefix == eveLogIndexPrefix {
		s.eveLogIndexName = currentIndexName
	} else if logIndexPrefix == pktLogIndexPrefix {
		s.pktLogIndexName = currentIndexName
	}
}
