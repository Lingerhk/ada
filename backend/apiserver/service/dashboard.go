package service

import (
	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/server"
	"ada/backend/cache"
	baseCommon "ada/backend/common"
	"context"
	"fmt"
	"maps"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ADAServiceV2) DashboardStats(ctx context.Context, in *v2.DashboardStatsReq) (*v2.DashboardStatsReply, error) {
	var domains []string
	if in.Domain == "all" {
		domainList, err := server.GetDomainList(s.env)
		if err != nil {
			logger.Errorf("get domain list err:%v", err)
			return nil, status.Error(codes.Internal, s.I18n("InternalError"))
		}
		for _, dm := range domainList {
			if dm.Status == baseCommon.DomainStatusInit {
				continue
			}
			domains = append(domains, dm.Name)
		}
	} else {
		domains = []string{in.Domain}
	}

	reply := &v2.DashboardStatsReply{
		Agent:    make(map[string]int32),
		Alert:    make(map[string]int32),
		Baseline: make(map[string]int32),
		Leak:     make(map[string]int32),
		Weakpwd:  make(map[string]int32),
		Asset:    make(map[string]int32),
		Rule:     make(map[string]int32),
		Event:    make(map[string]int32),
	}

	// Get alert counts by level (from AlertEventESDB collection)
	alertCounts, err := server.GetAlertCountsByLevel(s.env, domains)
	if err != nil {
		logger.Errorf("get alert counts err:%v", err)
	} else {
		maps.Copy(reply.Alert, alertCounts)
	}

	// Get baseline counts by level (from latest scan task)
	baselineCounts, err := server.GetBaselineCountsByLevel(s.env, domains)
	if err != nil {
		logger.Errorf("get baseline counts err:%v", err)
	} else {
		maps.Copy(reply.Baseline, baselineCounts)
	}

	// Get leak/vulnerability counts by level (from latest scan task)
	leakCounts, err := server.GetLeakCountsByLevel(s.env, domains)
	if err != nil {
		logger.Errorf("get leak counts err:%v", err)
	} else {
		maps.Copy(reply.Leak, leakCounts)
	}

	// Get weak password counts
	weakpwdCount, err := server.GetWeakPwdCount(s.env, domains)
	if err != nil {
		logger.Errorf("get weakpwd count err:%v", err)
	} else {
		reply.Weakpwd["total"] = weakpwdCount
	}

	// Get agent distribution (domains, sensors, dcs)
	agentDistribution, err := server.GetAgentDistribution(s.env)
	if err != nil {
		logger.Errorf("get agent distribution err:%v", err)
	} else {
		reply.Agent = agentDistribution
	}

	// Get asset distribution (users, computers, groups)
	assetDistribution, err := server.GetAssetDistribution(s.env, domains)
	if err != nil {
		logger.Errorf("get asset distribution err:%v", err)
	} else {
		reply.Asset = assetDistribution
	}

	// Get rule distribution (alert rules, activity rules)
	ruleDistribution, err := server.GetRuleDistribution(s.env)
	if err != nil {
		logger.Errorf("get rule distribution err:%v", err)
	} else {
		reply.Rule = ruleDistribution
	}

	// Get event distribution (alert events, alert activities)
	eventDistribution, err := server.GetEventDistribution(s.env)
	if err != nil {
		logger.Errorf("get event distribution err:%v", err)
	} else {
		reply.Event = eventDistribution
	}

	return reply, nil
}

func (s *ADAServiceV2) DashboardTrends(ctx context.Context, in *v2.DashboardTrendsReq) (*v2.DashboardTrendsReply, error) {
	return nil, nil
}

func (s *ADAServiceV2) DashboardLogStats(ctx context.Context, in *v2.DashboardLogStatsReq) (*v2.DashboardLogStatsReply, error) {
	var domains []string
	if in.Domain == "all" {
		domainList, err := server.GetDomainList(s.env)
		if err != nil {
			logger.Errorf("get domain list err:%v", err)
			return nil, status.Error(codes.Internal, s.I18n("InternalError"))
		}
		for _, dm := range domainList {
			if dm.Status == baseCommon.DomainStatusInit {
				continue
			}
			domains = append(domains, dm.Name)
		}
	} else {
		domains = []string{in.Domain}
	}

	// calculate time range
	now := time.Now()
	maxTs := now.Truncate(time.Minute).Unix() // Current minute timestamp
	durationMinutes := int64(in.Duration * 60)
	if durationMinutes <= 0 {
		durationMinutes = 60 // Default to 1 hour if duration is invalid
	}
	minTs := maxTs - (durationMinutes * 60) // start timestamp (seconds)

	minTsStr := strconv.FormatInt(minTs, 10)
	maxTsStr := strconv.FormatInt(maxTs, 10)

	// map to aggregate stats across domains
	statsMap := make(map[int64]*v2.DashboardLogStatsReplyLogStatsList)

	for _, domain := range domains {
		winLogStatsKey := fmt.Sprintf(cache.SysStatsWinLogKey, domain)
		pktlogStatsKey := fmt.Sprintf(cache.SysStatsPktLogKey, domain)

		// fetch data from redis zset
		winLogData, errWin := s.env.RedisCli.ZRangeByScoreWithScores(ctx, winLogStatsKey, &redis.ZRangeBy{
			Min: minTsStr,
			Max: maxTsStr,
		}).Result()
		if errWin != nil && errWin != redis.Nil {
			logger.Errorf("get winlog stats failed, key: %s, err: %v, will treat as 0 count", winLogStatsKey, errWin)
		}

		pktLogData, errPkt := s.env.RedisCli.ZRangeByScoreWithScores(ctx, pktlogStatsKey, &redis.ZRangeBy{
			Min: minTsStr,
			Max: maxTsStr,
		}).Result()
		if errPkt != nil && errPkt != redis.Nil {
			logger.Errorf("get pktlog stats failed, key: %s, err: %v, will treat as 0 count", pktlogStatsKey, errPkt)
		}

		// Populate map with winlog data for this domain
		for _, z := range winLogData {
			ts := int64(z.Score)
			count, _ := strconv.ParseInt(z.Member, 10, 32)
			if _, ok := statsMap[ts]; !ok {
				statsMap[ts] = &v2.DashboardLogStatsReplyLogStatsList{Ts: ts, WinlogCounts: int32(count), PktlogCounts: 0}
			} else {
				statsMap[ts].WinlogCounts += int32(count)
			}
		}

		// Populate map with pktlog data for this domain
		for _, z := range pktLogData {
			ts := int64(z.Score)
			count, _ := strconv.ParseInt(z.Member, 10, 32)
			if _, ok := statsMap[ts]; !ok {
				statsMap[ts] = &v2.DashboardLogStatsReplyLogStatsList{Ts: ts, WinlogCounts: 0, PktlogCounts: int32(count)}
			} else {
				statsMap[ts].PktlogCounts += int32(count)
			}
		}
	}

	// Fill missing timestamps and create the final list using aggregated data
	replyList := make([]*v2.DashboardLogStatsReplyLogStatsList, 0, durationMinutes) // Corrected type name
	for ts := minTs; ts <= maxTs; ts += 60 {
		if data, ok := statsMap[ts]; ok {
			replyList = append(replyList, data)
		} else {
			replyList = append(replyList, &v2.DashboardLogStatsReplyLogStatsList{ // Corrected type name
				Ts:           ts,
				WinlogCounts: 0,
				PktlogCounts: 0,
			})
		}
	}

	return &v2.DashboardLogStatsReply{List: replyList}, nil
}
