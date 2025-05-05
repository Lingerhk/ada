package service

import (
	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/server"
	"ada/backend/cache"
	baseCommon "ada/backend/common"
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ADAServiceV2) DashboardStats(ctx context.Context, in *v2.DashboardStatsReq) (*v2.DashboardStatsReply, error) {
	return nil, nil
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
