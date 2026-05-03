package core

import (
	"ada/engine/common"
	"ada/engine/flow"
	"ada/engine/sigma"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestSyncFlowEngineUsesFlowCacheKey(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	fr := flow.FlowRule{ID: "flow-mixed"}
	fr.Detection.CacheKey = map[string][]string{
		"winlog-0104-0001": {
			"TargetDomainName|domain",
			"TargetUserName|lower|trim",
		},
	}
	flowset := &flow.Ruleset{
		FlowRules:    []flow.FlowRule{fr},
		FlowRuleByID: map[string]*flow.FlowRule{fr.ID: &fr},
	}

	worker := &EngineWorker{
		ctx:      context.Background(),
		redisCli: rdb,
		Flowset:  flowset,
	}

	ctx := context.Background()
	if err := rdb.HSet(ctx, common.FlowRuleMapKey, "winlog-0104-0001", fr.ID).Err(); err != nil {
		t.Fatal(err)
	}

	result := sigma.Result{
		ID: "winlog-0104-0001",
		Fields: map[string]string{
			"TargetDomainName": "EXAMPLE",
			"TargetUserName":   " Alice ",
		},
		UniqueId:  "legacy-id",
		Timestamp: time.Now().UnixMilli(),
	}
	rule := &sigma.Rule{ID: "winlog-0104-0001", UniqueFields: []string{"TargetUserName"}}

	if err := worker.syncFlowEngine(ctx, "es1", "mongo1", "dc01.example.com", result, rule); err != nil {
		t.Fatal(err)
	}

	keys := flowset.BuildFlowInstanceKeys(fr.ID, result.ID, result.Fields, "dc01.example.com", result.UniqueId)
	if len(keys) != 1 {
		t.Fatalf("expected one flow cache key, got %v", keys)
	}

	expectedZSet := fmt.Sprintf("%s:%s_%s", common.FlowInstancePrefixKey, fr.ID, keys[0])
	if exists := rdb.Exists(ctx, expectedZSet).Val(); exists != 1 {
		t.Fatalf("expected flow cache zset %s to exist", expectedZSet)
	}

	legacyZSet := fmt.Sprintf("%s:%s_%s", common.FlowInstancePrefixKey, fr.ID, result.UniqueId)
	if exists := rdb.Exists(ctx, legacyZSet).Val(); exists != 0 {
		t.Fatalf("expected legacy unique_id zset to be unused")
	}

	activeKey := fmt.Sprintf("%s:%s", common.FlowActiveSetPrefixKey, fr.ID)
	if ok := rdb.SIsMember(ctx, activeKey, expectedZSet).Val(); !ok {
		t.Fatalf("expected active set to include %s", expectedZSet)
	}

	activityCache := fmt.Sprintf("%s_%s", common.AlertActivityCachePrefix, "mongo1")
	if sid := rdb.HGet(ctx, activityCache, "sid").Val(); sid != result.ID {
		t.Fatalf("expected activity cache sid %s, got %s", result.ID, sid)
	}
}
