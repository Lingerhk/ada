package flow

import (
	"context"
	logger "github.com/sirupsen/logrus"
	"time"
)

func (r *Ruleset) matchEventMultiPkt(ctx context.Context, fr FlowRule, flowInstances []string) {
	for _, insId := range flowInstances {
		stop := time.Now().UnixNano() / 1e6

		logger.Debugf("11----handle matchEventMultiPkt instance_id %s", insId)

		// 取最新winSize内的所有事件, 默认去当前时间4分钟内的所有事件活动
		activities, err := r.getFlowActivitiesByWinSize(ctx, insId, fr.Detection.WinSizeTs, stop)
		if err != nil {
			logger.Warnf("get flow events by win_size err:%v, will ignore this event!", err)
			continue
		}
		if len(activities) == 0 {
			//logger.Debug("get flow events by win_size is empty, will ignore this event!")
			continue
		}

		validSets := r.extractActivities(activities, fr.Detection.SigmaRules, fr.Detection.WinSizeTs, fr.Detection.Sorted)
		if len(validSets) == 0 {
			//logger.Debug("validSets is empty, will ignore this event!")
			continue
		}

		matchedActivities, matched := r.matchByActivities(ctx, activities, validSets, fr.Detection.MatchBy)
		if !matched {
			continue
		}

		// 匹配到flow告警
		logger.Debugf("matched flow from activities: %v", matchedActivities)

		if err := r.storeEvent(ctx, insId, fr, matchedActivities); err != nil {
			logger.Warnf("store event(multi-eve) err:%v, will ignore this flow instance!", err)
		}

		if err := r.redisCli.Del(ctx, insId).Err(); err != nil {
			logger.Warnf("delete flow instance(multi-pkt) err:%v", err)
		}
	}
}
