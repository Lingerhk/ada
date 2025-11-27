package service

import (
	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/server"
	"ada/backend/apiserver/util"
	"ada/backend/cache"
	"ada/backend/common"
	"ada/infra/base"
	"ada/infra/license"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-cmd/cmd"
	"github.com/shirou/gopsutil/host"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// readCurrentRuleVersion reads the current rule version from current_version.txt
func readCurrentRuleVersion() string {
	versionFilePath := filepath.Join(common.ROOT_PATH, "download", "rules", "current_version.txt")

	data, err := os.ReadFile(versionFilePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Warnf("Failed to read current rule version: %v", err)
		}
		return "0"
	}

	return strings.TrimSpace(string(data))
}

// fetchCloudRuleVersion fetches the cloud rule version from remote server
// upgradeProxy: whether to use proxy for upgrade requests
// httpProxy: HTTP proxy URL
func fetchCloudRuleVersion(upgradeSrv string, upgradeProxy bool, httpProxy string) string {
	if upgradeSrv == "" {
		return ""
	}

	// Build URL
	baseURL := strings.TrimSuffix(upgradeSrv, "/")
	requestURL := fmt.Sprintf("%s/rule/version/latest.json", baseURL)

	// Create HTTP client with timeout and proxy support
	var client *http.Client
	if upgradeProxy && httpProxy != "" {
		// Use proxy if enabled
		transport := &http.Transport{}
		if proxyURL, err := url.Parse(httpProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
		client = &http.Client{
			Timeout:   5 * time.Second,
			Transport: transport,
		}
	} else {
		// No proxy
		client = &http.Client{
			Timeout: 5 * time.Second,
		}
	}

	resp, err := client.Get(requestURL)
	if err != nil {
		logger.Warnf("Failed to fetch cloud rule version from %s: %v", requestURL, err)
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Warnf("Failed to fetch cloud rule version: status %d", resp.StatusCode)
		return ""
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warnf("Failed to read cloud version response: %v", err)
		return ""
	}

	// Parse JSON
	var versionInfo struct {
		Version string `json:"version"`
		MD5     string `json:"md5"`
	}

	if err := json.Unmarshal(body, &versionInfo); err != nil {
		logger.Warnf("Failed to parse cloud version JSON: %v", err)
		return ""
	}

	return versionInfo.Version
}

func (s *ADAServiceV2) GetSystemInfo(ctx context.Context, in *v2.GetSystemInfoReq) (*v2.GetSystemInfoReply, error) {
	sys, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err: %s", err)
		return nil, status.Error(codes.Internal, s.I18n("System.GetSystemInfoFailed"))
	}

	cpuTotal := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "cpu_cores").Val()
	memTotal := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "mem_total").Val()
	diskTotal := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "disk_total").Val()
	loadAverage := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "local_15m").Val()
	upTime := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "uptime").Val()
	timestamp := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "timestamp").Val()
	esHealth := s.env.RedisCli.HGet(ctx, cache.SysStatsInfoKey, "es_check_stats").Val()

	hostStat, err := host.Info()
	if err == nil {
		upTime = strconv.FormatUint(hostStat.Uptime, 10)
	}

	upgradeRule := "false"
	if sys.UpgradeRule {
		upgradeRule = "true"
	}

	// Read current rule version from file
	currentRuleVer := readCurrentRuleVersion()

	// Parse system proxy from map to proto message
	var systemProxy *v2.SystemProxyInfo
	upgradeProxy := false
	httpProxy := ""
	if sys.SystemProxy != nil {
		systemProxy = &v2.SystemProxyInfo{
			HttpProxy:    sys.SystemProxy["http_proxy"],
			HttpsProxy:   sys.SystemProxy["https_proxy"],
			UpgradeProxy: sys.SystemProxy["upgrade_proxy"] == "true",
			NotifyProxy:  sys.SystemProxy["notify_proxy"] == "true",
		}
		upgradeProxy = sys.SystemProxy["upgrade_proxy"] == "true"
		httpProxy = sys.SystemProxy["http_proxy"]
	}

	// Fetch cloud rule version if upgradeRule is enabled and upgradeSrv is set
	cloudRuleVer := ""
	if sys.UpgradeRule && sys.UpgradeSrv != "" {
		cloudRuleVer = fetchCloudRuleVersion(sys.UpgradeSrv, upgradeProxy, httpProxy)
	}

	ret := v2.GetSystemInfoReply{
		SystemIP:          sys.SystemIP,
		SystemName:        sys.SystemName,
		SystemIcon:        sys.SystemIcon,
		SystemVersion:     sys.SystemVersion,
		SystemInstallTm:   sys.CreateTm.String(),
		SystemUpgradeTm:   sys.UpgradeTm.String(),
		SystemCpuTotal:    cpuTotal,
		SystemMemTotal:    memTotal,
		SystemDiskTotal:   diskTotal,
		SystemLoadAverage: loadAverage,
		SystemBootTime:    upTime,
		SystemEsHealth:    esHealth,
		SystemTimestamp:   timestamp,
		SystemNtpAddress:  sys.NtpAddress,
		SystemLanguage:    sys.SystemLanguage,
		StatsCfg:          sys.StatsCfg,
		UpgradeSrv:        sys.UpgradeSrv,
		UpgradeRule:       upgradeRule,
		CurrentRuleVer:    currentRuleVer,
		CloudRuleVer:      cloudRuleVer,
		SystemProxy:       systemProxy,
	}

	return &ret, nil
}

func (s *ADAServiceV2) GetSystemIcon(ctx context.Context, in *v2.GetSystemIconReq) (*v2.GetSystemIconReply, error) {
	si, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("System.GetSystemInfoFailed"))
	}

	if si.SystemIcon == "" {
		originIcon := path.Join(common.ROOT_PATH, "static", "favicon.png")
		fCnt, err := os.ReadFile(originIcon)
		if err != nil {
			logger.Warnf("read file err:%v", err)
			return nil, status.Error(codes.Internal, s.I18n("System.GetSystemIconFailed"))
		}
		iconB64 := base64.StdEncoding.EncodeToString(fCnt)
		err = server.UpdateSystemCfg(s.env, si.ID, "", "", iconB64, "", "")
		if err != nil {
			logger.Warnf("update system info err:%v", err)
			return nil, status.Error(codes.Internal, s.I18n("System.UpdateSystemIconFailed"))
		}
		return &v2.GetSystemIconReply{Icon: iconB64}, nil
	}

	return &v2.GetSystemIconReply{Icon: si.SystemIcon}, nil
}

func (s *ADAServiceV2) UpdateSystemLanguage(ctx context.Context, in *v2.UpdateSystemLanguageReq) (*v2.UpdateSystemLanguageReply, error) {
	ret := &v2.UpdateSystemLanguageReply{
		Result: RESP_FAILED,
	}

	// update language in db
	err := server.UpdateLanguage(s.env, in.Language)
	if err != nil {
		logger.Warnf("update system language err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("System.UpdateSystemLanguageFailed"))
	}

	s.language = in.Language
	ret.Result = RESP_SUCCESS

	return ret, nil
}

func (s *ADAServiceV2) UpdateSystemCfg(ctx context.Context, in *v2.UpdateSystemCfgReq) (*v2.UpdateSystemCfgReply, error) {
	ret := &v2.UpdateSystemCfgReply{
		Result: RESP_FAILED,
	}

	si, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err: %s", err)
		return ret, status.Error(codes.Internal, s.I18n("System.GetSystemInfoFailed"))
	}

	// Validate and process NTP if provided
	if in.Ntp != "" {
		domainReg := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`
		domainRegex := regexp.MustCompile(domainReg)
		if net.ParseIP(in.Ntp) == nil && !domainRegex.MatchString(in.Ntp) {
			logger.Infof("invalid ntp address %s", in.Ntp)
			return ret, status.Error(codes.InvalidArgument, s.I18n("System.UpdateNtpAddressFailed"))
		}

		// call system command to update ntp address
		out, err := exec.Command("sudo", "ntpdate", in.Ntp).Output()
		if err != nil {
			logger.Warnf("update ntp(%s) err:%v, stdout:%s", in.Ntp, err, out)
			return ret, status.Error(codes.Internal, s.I18n("System.UpdateNtpAddressFailed"))
		}
	}

	// Validate and process icon file if provided
	if in.File != "" {
		var iconTypes = []string{"jpg", "jpeg", "png"}

		iconByte, err := base64.StdEncoding.DecodeString(in.File)
		if err != nil {
			logger.Warnf("decode string err: %s", err)
			return ret, status.Error(codes.Internal, s.I18n("System.UpdateSystemIconFailed"))
		}

		// 限制大小
		if len(iconByte)/8 > fileMaxSize {
			return ret, status.Error(codes.Internal, s.I18n("System.UpdateIconTooLarge"))
		}

		// Icon类型判断
		contentType := http.DetectContentType(iconByte)
		fileExt := strings.Split(contentType, "/")[1]

		if !slices.Contains(iconTypes, strings.ToLower(fileExt)) {
			logger.Warnf("invalid icon type %s", fileExt)
			return ret, status.Error(codes.Internal, s.I18n("System.UpdateIconInvalidType"))
		}
	}

	// Update system configuration in database
	err = server.UpdateSystemCfg(s.env, si.ID, in.Ntp, in.SystemIP, in.File, in.UpgradeSrv, in.UpgradeRule)
	if err != nil {
		logger.Warnf("update system cfg err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("System.UpdateSystemCfgFailed"))
	}

	ret.Result = RESP_SUCCESS

	return ret, nil
}

func (s *ADAServiceV2) GetSystemStats(ctx context.Context, in *v2.GetSystemStatsReq) (*v2.GetSystemStatsReply, error) {
	var statsCount int64
	if in.Scope == "2h" {
		statsCount = 60 * 2
	} else if in.Scope == "24h" {
		statsCount = 60 * 24
	}

	rdxKey := fmt.Sprintf("ada:server:stats:%s", in.Type)

	length, err := s.env.RedisCli.LLen(ctx, rdxKey).Result()
	if err != nil {
		logger.Errorf("redis get length(%s) err: %s", rdxKey, err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	start := 0
	if length > statsCount {
		start = int(length - statsCount)
	}
	vals, err := s.env.RedisCli.LRange(ctx, rdxKey, int64(start), -1).Result()
	if err != nil {
		logger.Errorf("redis get stats err: %s", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	ret := v2.GetSystemStatsReply{}
	si := []*v2.StatsInfo{}
	for _, val := range vals {
		parts := strings.SplitN(val, ":", 2)
		if len(parts) != 2 {
			continue
		}
		si = append(si, &v2.StatsInfo{Timestamp: parts[0], Value: parts[1]})
	}
	ret.Stats = si

	return &ret, nil
}

func (s *ADAServiceV2) ListAuditLog(ctx context.Context, in *v2.ListAuditLogReq) (*v2.ListAuditLogReply, error) {
	query := bson.D{}
	// 非超级管理员只允许查看自己的日志
	if !s.IsSuper(ctx) {
		query = append(query, bson.E{Key: "username", Value: s.GetUser(ctx)})
	}
	// 0为正常 1为删除
	query = append(query, bson.E{Key: "status", Value: 0})

	if len(in.StartTm) > 0 && len(in.EndTm) > 0 {
		startTime, err := time.Parse("2006-01-02 15:04:05", in.StartTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, err
		}
		endTime, err := time.Parse("2006-01-02 15:04:05", in.EndTm)
		if err != nil {
			logger.Errorf("parse time err:%v", err)
			return nil, err
		}

		//起止日期相同的话截止日期+1，前端没有传时分秒
		if startTime == endTime {
			endTime = endTime.AddDate(0, 0, 1)
		}

		query = append(query, bson.E{Key: "create_tm", Value: bson.M{"$gte": startTime.Add(-time.Hour * 8), "$lte": endTime.Add(-time.Hour * 8).Add(time.Second)}})
	}

	if len(in.Keyword) > 0 {
		var bm []bson.M
		bm = append(bm, bson.M{
			"username": bson.M{"$regex": util.Escaping(in.Keyword), "$options": "i"},
		})
		bm = append(bm, bson.M{
			"client_ip": bson.M{"$regex": util.Escaping(in.Keyword), "$options": "i"},
		})

		query = append(query, bson.E{Key: "$or", Value: bm})
	}

	if len(in.FilterEvent) > 0 {
		query = append(query, bson.E{Key: "event", Value: bson.M{"$in": in.FilterEvent}})
	}

	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	sort := bson.M{"create_tm": -1}
	if in.CreateSort == 1 || in.CreateSort == -1 {
		sort = bson.M{"create_tm": in.CreateSort}
	}
	res, total, err := server.FindAllAuditLog(s.env, query, sort, limit, offset)
	if err != nil {
		logger.Errorf("query listAuditLog err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}
	ret := v2.ListAuditLogReply{}
	for _, r := range res {
		ret.List = append(ret.List,
			&v2.ListAuditLogReply_Details{
				ID:          r.ID.Hex(),
				Username:    r.Username,
				ClientIp:    r.ClientIp,
				Event:       r.Event,
				EventArgs:   r.EventArgs,
				EventResult: r.EventResult,
				CreateTm:    r.CreateTm.String(),
			})
	}
	ret.Page = &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: int32(total)}
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}
	return &ret, nil
}

func (s *ADAServiceV2) NetworkDebug(ctx context.Context, in *v2.NetworkDebugReq) (*v2.NetworkDebugReply, error) {
	// Validate target using allowlist approach (only allow valid hostnames, IPs, or IP:port)
	// This is more secure than blocklist approach

	// Regex patterns for validation
	// IPv4 address pattern
	ipv4Pattern := `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`
	// IPv6 address pattern (simplified)
	ipv6Pattern := `^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$`
	// Hostname pattern (RFC 1123 compliant)
	hostnamePattern := `^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`
	// Port pattern (1-65535)
	portPattern := `^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$`

	ipv4Regex := regexp.MustCompile(ipv4Pattern)
	ipv6Regex := regexp.MustCompile(ipv6Pattern)
	hostnameRegex := regexp.MustCompile(hostnamePattern)
	portRegex := regexp.MustCompile(portPattern)

	// Length limit
	if len(in.Target) > 253 { // Max hostname length per RFC
		return nil, status.Error(codes.InvalidArgument, s.I18n("System.NetworkDebug.TargetTooLong"))
	}

	// Validate command type
	validTypes := []string{"ping", "nslookup", "traceroute", "nc"}
	if !slices.Contains(validTypes, in.Type) {
		return nil, status.Error(codes.InvalidArgument, s.I18n("System.NetworkDebug.InvalidType"))
	}

	diagCmd := &cmd.Cmd{}
	switch in.Type {
	case "ping", "nslookup", "traceroute":
		// Validate target is a valid IP or hostname
		if !ipv4Regex.MatchString(in.Target) && !ipv6Regex.MatchString(in.Target) && !hostnameRegex.MatchString(in.Target) {
			return nil, status.Error(codes.InvalidArgument, s.I18n("System.NetworkDebug.InvalidTarget"))
		}
		switch in.Type {
		case "ping":
			diagCmd = cmd.NewCmd("ping", "-c", "5", in.Target)
		case "nslookup":
			diagCmd = cmd.NewCmd("nslookup", in.Target)
		case "traceroute":
			diagCmd = cmd.NewCmd("traceroute", "-q", "1", "-m", "10", in.Target)
		}
	case "nc":
		// For nc, target must be in format host:port
		lastColon := strings.LastIndex(in.Target, ":")
		if lastColon == -1 {
			return nil, status.Error(codes.InvalidArgument, s.I18n("System.NetworkDebug.NcSyntax"))
		}
		host := in.Target[:lastColon]
		port := in.Target[lastColon+1:]

		// Validate host
		if !ipv4Regex.MatchString(host) && !ipv6Regex.MatchString(host) && !hostnameRegex.MatchString(host) {
			return nil, status.Error(codes.InvalidArgument, s.I18n("System.NetworkDebug.InvalidTarget"))
		}
		// Validate port
		if !portRegex.MatchString(port) {
			return nil, status.Error(codes.InvalidArgument, s.I18n("System.NetworkDebug.InvalidPort"))
		}
		diagCmd = cmd.NewCmd("nc", "-vz", "-w", "10", host, port)
	}

	statusChan := diagCmd.Start()
	timeoutCh := make(chan string)
	// Stop command after 120 second
	go func() {
		<-time.After(time.Second * 60)
		diagCmd.Stop()
		timeoutCh <- "timout"
	}()

	// Check if command is done
	select {
	case <-timeoutCh:
		//timeout
		return nil, status.Error(codes.DeadlineExceeded, s.I18n("System.NetworkDebug.Timeout"))
	case <-statusChan:
		// done
	default:
		// no, still running
	}
	final := <-statusChan
	result := ""
	result += strings.Join(final.Stdout, "\n")
	result += strings.Join(final.Stderr, "\n")
	return &v2.NetworkDebugReply{Result: result}, nil
}

func (s *ADAServiceV2) GetLicense(ctx context.Context, in *v2.GetLicenseReq) (*v2.GetLicenseReply, error) {
	ret := v2.GetLicenseReply{Trait: license.GetTrait()}

	licer, err := license.NewAdaLicense(s.env.RedisCli)
	if err != nil {
		logger.Errorf("new license client err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("System.License.GetLicenseFailed"))
	}

	licInfo := licer.GetInfo()
	ret.Assets = int32(licInfo.Count)
	ret.EndTime = licInfo.EndTm

	sysInfo, err := server.GetSystemInfo(s.env)
	if err != nil {
		return &ret, err
	}
	ret.Version = sysInfo.SystemVersion
	ret.Partner = sysInfo.SystemName

	return &ret, nil
}

func (s *ADAServiceV2) UpdateLicense(ctx context.Context, in *v2.UpdateLicenseReq) (*v2.UpdateLicenseReply, error) {
	ret := v2.UpdateLicenseReply{Result: RESP_FAILED}

	if len(in.LicenseKey) != 336 {
		logger.Warnf("invalid license key:%s", in.LicenseKey)
		return &ret, status.Error(codes.Internal, s.I18n("System.License.InvalidLicenseKey"))
	}

	licer, err := license.NewAdaLicense(s.env.RedisCli)
	if err != nil {
		logger.Errorf("new license client err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("System.License.UpdateLicenseFailed"))
	}

	err = licer.UpdateCnt(in.LicenseKey)
	if err != nil {
		logger.Errorf("update license cnt(%s) err:%v", in.LicenseKey, err)
		return &ret, status.Error(codes.Internal, s.I18n("System.License.UpdateLicenseFailed"))
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) SetSystemStatsCfg(ctx context.Context, in *v2.SetSystemStatsCfgReq) (*v2.SetSystemStatsCfgReply, error) {
	sys, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err: %s", err)
		return nil, status.Error(codes.Internal, s.I18n("System.GetSystemInfoFailed"))
	}

	var ret = v2.SetSystemStatsCfgReply{Result: RESP_FAILED}

	for statsKey, statsVal := range in.Stats {
		exist, err := base.Contain(statsKey, sys.StatsCfg)
		if err != nil || !exist {
			logger.Warnf("invalid stats item %s", statsKey)
			return &ret, status.Error(codes.InvalidArgument, s.I18n("System.InvalidStatsItem", statsKey))
		}

		// update stats cfg
		sys.StatsCfg[statsKey] = statsVal
	}

	err = server.UpdateStatsCfg(s.env, sys.StatsCfg)
	if err != nil {
		logger.Errorf("update stats cfg err: %s", err)
		return &ret, status.Error(codes.Internal, s.I18n("System.UpdateStatsCfgFailed"))
	}

	// update stats cfg in redis
	err = s.env.RedisCli.HMSet(ctx, cache.SysStatsCfgKey, sys.StatsCfg).Err()
	if err != nil {
		logger.Errorf("update stats cfg cache err: %s", err)
		return &ret, status.Error(codes.Internal, s.I18n("System.UpdateStatsCfgFailed"))
	}

	ret.Result = RESP_SUCCESS

	return &ret, nil
}

func (s *ADAServiceV2) ListSystemLogs(ctx context.Context, in *v2.ListSystemLogsReq) (*v2.ListSystemLogsReply, error) {
	ret := &v2.ListSystemLogsReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 0},
		Exhausted: true,
	}

	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	logList, total, err := server.FindAllSystemLogs(s.env, in.Level, in.Module, in.Search, in.StartTm, in.EndTm, in.SortTime, limit, offset)
	if err != nil {
		logger.Errorf("find system logs failed,err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("QueryFailed"))
	}

	for _, log := range logList {
		ret.List = append(ret.List, &v2.ListSystemLogsReply_Details{
			Time:   log.Time,
			Level:  log.Level,
			Module: log.Module,
			Msg:    log.Msg,
			Func:   log.Func,
			File:   log.File,
		})
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	}
	return ret, nil
}

func (s *ADAServiceV2) GetSystemProxy(ctx context.Context, in *v2.GetSystemProxyReq) (*v2.GetSystemProxyReply, error) {
	sys, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err: %s", err)
		return nil, status.Error(codes.Internal, s.I18n("System.GetSystemInfoFailed"))
	}

	// Parse system proxy from map to proto message
	var systemProxy *v2.SystemProxyInfo
	if sys.SystemProxy != nil {
		systemProxy = &v2.SystemProxyInfo{
			HttpProxy:    sys.SystemProxy["http_proxy"],
			HttpsProxy:   sys.SystemProxy["https_proxy"],
			UpgradeProxy: sys.SystemProxy["upgrade_proxy"] == "true",
			NotifyProxy:  sys.SystemProxy["notify_proxy"] == "true",
		}
	} else {
		// Return empty proxy info if not configured
		systemProxy = &v2.SystemProxyInfo{
			HttpProxy:    "",
			HttpsProxy:   "",
			UpgradeProxy: false,
			NotifyProxy:  false,
		}
	}

	ret := v2.GetSystemProxyReply{
		SystemProxy: systemProxy,
	}

	return &ret, nil
}

func (s *ADAServiceV2) UpdateSystemProxy(ctx context.Context, in *v2.UpdateSystemProxyReq) (*v2.UpdateSystemProxyReply, error) {
	ret := &v2.UpdateSystemProxyReply{
		Result: RESP_FAILED,
	}

	// Update system proxy configuration in database
	err := server.UpdateSystemProxy(s.env, in.HttpProxy, in.HttpsProxy, in.UpgradeProxy, in.NotifyProxy)
	if err != nil {
		logger.Warnf("update system proxy err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("System.UpdateSystemProxyFailed"))
	}

	ret.Result = RESP_SUCCESS

	return ret, nil
}
