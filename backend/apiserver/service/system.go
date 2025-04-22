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
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-cmd/cmd"
	"github.com/shirou/gopsutil/host"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ADAServiceV2) GetSystemInfo(ctx context.Context, in *v2.GetSystemInfoReq) (*v2.GetSystemInfoReply, error) {
	sys, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err: %s", err)
		return nil, status.Errorf(codes.Internal, "未能找信息")
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

	ret := v2.GetSystemInfoReply{
		Ip:                sys.IP,
		Netmask:           sys.NetMask,
		Gateway:           sys.Gateway,
		Dns:               sys.DNS,
		SystemName:        sys.SystemName,
		CompanyName:       sys.CompanyName,
		CompanyWebsite:    sys.CompanyWebsite,
		CompanyIcon:       sys.CompanyIcon,
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
	}

	return &ret, nil
}

func (s *ADAServiceV2) GetCompanyIcon(ctx context.Context, in *v2.GetCompanyIconReq) (*v2.GetCompanyIconReply, error) {
	si, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err:%v", err)
		return nil, status.Error(codes.Internal, "获取系统信息异常")
	}

	if si.CompanyIcon == "" {
		originIcon := path.Join(common.RESOURCE_PATH, "image", "favicon.png")
		fCnt, err := os.ReadFile(originIcon)
		if err != nil {
			logger.Warnf("read file err:%v", err)
			return nil, status.Error(codes.Internal, "获取原始图标异常")
		}
		iconB64 := base64.StdEncoding.EncodeToString(fCnt)
		err = server.UpdateCompanyIcon(s.env, si.ID, iconB64)
		if err != nil {
			logger.Warnf("update system info err:%v", err)
			return nil, status.Error(codes.Internal, "更新图标异常")
		}
		return &v2.GetCompanyIconReply{Icon: si.CompanyIcon}, nil
	}

	return &v2.GetCompanyIconReply{Icon: si.CompanyIcon}, nil
}

func (s *ADAServiceV2) UpdateCompanyIcon(ctx context.Context, in *v2.UpdateCompanyIconReq) (*v2.UpdateCompanyIconReply, error) {
	var iconTypes = []string{"jpg", "jpeg", "png"}

	ret := &v2.UpdateCompanyIconReply{
		Result: RESP_FAILED,
	}

	iconByte, err := base64.StdEncoding.DecodeString(in.File)
	if err != nil {
		logger.Warnf("decode string err: %s", err)
		return ret, status.Error(codes.Internal, "上传图标失败")
	}

	// 限制大小
	if len(iconByte)/8 > fileMaxSize {
		return ret, status.Error(codes.Internal, "请上传小于512KB的图片文件")
	}

	// Icon类型判断
	contentType := http.DetectContentType(iconByte)
	fileExt := strings.Split(contentType, "/")[1]

	allowExt := false
	for _, iconExt := range iconTypes {
		if strings.ToLower(fileExt) == iconExt {
			allowExt = true
			break
		}
	}
	if !allowExt {
		logger.Warnf("invalid icon type %s", fileExt)
		return ret, status.Error(codes.Internal, "仅限上传jpg/jpeg/png格式的图片文件")
	}

	si, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Warnf("get system info err:%v", err)
		return ret, status.Error(codes.Internal, "获取系统信息失败")
	}

	err = server.UpdateCompanyIcon(s.env, si.ID, in.File)
	if err != nil {
		logger.Warnf("get system info err:%v", err)
		return ret, status.Error(codes.Internal, "更新图标失败")
	}

	ret.Result = RESP_SUCCESS

	return ret, nil
}

func (s *ADAServiceV2) UpdateNtpAddress(ctx context.Context, in *v2.UpdateNtpAddressReq) (*v2.UpdateNtpAddressReply, error) {
	ret := &v2.UpdateNtpAddressReply{
		Result: RESP_FAILED,
	}

	domainReg := `^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`
	domainRegex := regexp.MustCompile(domainReg)
	if net.ParseIP(in.Ntp) == nil && !domainRegex.MatchString(in.Ntp) {
		logger.Infof("invalid ntp address %s", in.Ntp)
		return ret, status.Error(codes.InvalidArgument, "无效的NTP地址")
	}

	// call system command to update ntp address
	out, err := exec.Command("sudo", "ntpdate", in.Ntp).Output()
	if err != nil {
		logger.Warnf("update ntp(%s) err:%v, stdout:%s", in.Ntp, err, out)
		return ret, status.Error(codes.Internal, "更新NTP地址失败")
	}

	// update ntp address in db
	err = server.UpdateNtpAddress(s.env, in.Ntp)
	if err != nil {
		logger.Warnf("update ntp address(%s) err:%v", in.Ntp, err)
		return ret, status.Error(codes.Internal, "更新NTP地址失败")
	}

	ret.Result = RESP_SUCCESS

	return ret, nil
}

func (s *ADAServiceV2) UpdateSystemLanguage(ctx context.Context, in *v2.UpdateSystemLanguageReq) (*v2.UpdateSystemLanguageReply, error) {
	ret := &v2.UpdateSystemLanguageReply{
		Result: RESP_FAILED,
	}

	// update language in db
	err := server.UpdateLanguage(s.env, in.Language)
	if err != nil {
		logger.Warnf("update system language err:%v", err)
		return ret, status.Error(codes.Internal, "更新语言失败")
	}

	// update language in redis
	err = s.env.RedisCli.Set(ctx, "ada:server:system_language", in.Language, 0).Err()
	if err != nil {
		logger.Warnf("update system language err:%v", err)
		return ret, status.Error(codes.Internal, "更新语言失败")
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
		return nil, status.Errorf(codes.Internal, "内部错误")
	}

	start := 0
	if length > statsCount {
		start = int(length - statsCount)
	}
	vals, err := s.env.RedisCli.LRange(ctx, rdxKey, int64(start), -1).Result()
	if err != nil {
		logger.Errorf("redis get stats err: %s", err)
		return nil, status.Errorf(codes.Internal, "内部错误")
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
		return nil, status.Errorf(codes.Internal, "查询审核日志失败")
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
	//校验提交参数非法
	// 如果存在特殊字符，抛出异常，防止系统命令执行
	for _, ch := range []string{" ", "|", "&", ">", ">>", ";", ",", "^", "*", "$", "%", "/"} {
		if strings.Contains(in.Target, ch) {
			return nil, status.Error(codes.InvalidArgument, "包含非法字符串")
		}
	}
	if len(in.Target) > 25 {
		return nil, status.Error(codes.InvalidArgument, "Target太长(超过25字符)")
	}

	diagCmd := &cmd.Cmd{}
	switch in.Type {
	case "ping":
		diagCmd = cmd.NewCmd("ping", "-c", "5", in.Target)
	case "nslookup":
		diagCmd = cmd.NewCmd("nslookup", in.Target)
	case "traceroute":
		diagCmd = cmd.NewCmd("traceroute", "-q", "1", "-m", "10", in.Target)
	case "nc":
		parts := strings.Split(in.Target, ":")
		if len(parts) != 2 {
			return nil, status.Error(codes.InvalidArgument, "NC命令语法为IP:Port")
		}
		diagCmd = cmd.NewCmd("nc", "-vz", "-w", "10", parts[0], parts[1])
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
		return nil, status.Error(codes.InvalidArgument, "请求命令超时(限制60秒)")
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
		return &ret, status.Error(codes.Internal, "服务器内部错误")
	}

	licInfo := licer.GetInfo()
	ret.Assets = int32(licInfo.Count)
	ret.EndTime = licInfo.EndTm

	sysInfo, err := server.GetSystemInfo(s.env)
	if err != nil {
		return &ret, err
	}
	ret.Version = sysInfo.SystemVersion
	ret.Partner = sysInfo.CompanyName

	return &ret, nil
}

func (s *ADAServiceV2) UpdateLicense(ctx context.Context, in *v2.UpdateLicenseReq) (*v2.UpdateLicenseReply, error) {
	ret := v2.UpdateLicenseReply{Result: RESP_FAILED}

	if len(in.LicenseKey) != 336 {
		logger.Warnf("invalid license key:%s", in.LicenseKey)
		return &ret, status.Error(codes.Internal, "License长度错误")
	}

	licer, err := license.NewAdaLicense(s.env.RedisCli)
	if err != nil {
		logger.Errorf("new license client err:%v", err)
		return &ret, status.Error(codes.Internal, "服务器内部错误")
	}

	err = licer.UpdateCnt(in.LicenseKey)
	if err != nil {
		logger.Errorf("update license cnt(%s) err:%v", in.LicenseKey, err)
		return &ret, status.Error(codes.Internal, "更新License失败")
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) SetSystemStatsCfg(ctx context.Context, in *v2.SetSystemStatsCfgReq) (*v2.SetSystemStatsCfgReply, error) {
	sys, err := server.GetSystemInfo(s.env)
	if err != nil {
		logger.Errorf("get system info err: %s", err)
		return nil, status.Errorf(codes.Internal, "未能找信息")
	}

	var ret = v2.SetSystemStatsCfgReply{Result: RESP_FAILED}

	for statsKey, statsVal := range in.Stats {
		exist, err := base.Contain(statsKey, sys.StatsCfg)
		if err != nil || !exist {
			logger.Warnf("invalid stats item %s", statsKey)
			return &ret, status.Error(codes.InvalidArgument, "无效的监控项:"+statsKey)
		}

		// update stats cfg
		sys.StatsCfg[statsKey] = statsVal
	}

	err = server.UpdateStatsCfg(s.env, sys.StatsCfg)
	if err != nil {
		logger.Errorf("update stats cfg err: %s", err)
		return &ret, status.Errorf(codes.Internal, "更新监控配置失败")
	}

	// update stats cfg in redis
	err = s.env.RedisCli.HMSet(ctx, cache.SysStatsCfgKey, sys.StatsCfg).Err()
	if err != nil {
		logger.Errorf("update stats cfg cache err: %s", err)
		return &ret, status.Errorf(codes.Internal, "更新监控配置失败")
	}

	ret.Result = RESP_SUCCESS

	return &ret, nil
}
