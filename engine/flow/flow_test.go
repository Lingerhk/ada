package flow

import (
	"ada/engine/common"
	"ada/infra/mongo"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

var errUnsupportedMongo = errors.New("unsupported mongo operation")

type fakeMongoAdaptor struct {
	mu   sync.Mutex
	docs map[string][]any
}

func newFakeMongoAdaptor() *fakeMongoAdaptor {
	return &fakeMongoAdaptor{docs: make(map[string][]any)}
}

func (f *fakeMongoAdaptor) Connect(ctx context.Context, uri, db string) error { return nil }
func (f *fakeMongoAdaptor) Disconnect(ctx context.Context)                    {}
func (f *fakeMongoAdaptor) SetPoolLimit(limit uint64)                         {}
func (f *fakeMongoAdaptor) FindOne(ctx context.Context, name string, query, result any) (error, bool) {
	return errUnsupportedMongo, false
}
func (f *fakeMongoAdaptor) Find(ctx context.Context, name string, query, result any, limit int64) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindAll(ctx context.Context, name string, query, result any) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindByLimitAndSkip(ctx context.Context, name string, query, result any, limit, skip int64) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindWithSelect(ctx context.Context, name string, query, selection, result any, limit int64) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindSelect(ctx context.Context, name string, query, selection, result any) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindWithMultiple(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindCount(ctx context.Context, name string, query any) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.docs[name])), nil
}
func (f *fakeMongoAdaptor) FindSortByLimitAndSkip(ctx context.Context, name string, query, sorter, result any, limit, skip int64) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindWithAggregation(ctx context.Context, name string, pipeline, result any) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) Remove(ctx context.Context, name string, query any, multi bool) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) RemoveById(ctx context.Context, name string, id any) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) Drop(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.docs, name)
	return nil
}
func (f *fakeMongoAdaptor) Insert(ctx context.Context, name string, doc any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.docs[name] = append(f.docs[name], doc)
	return nil
}
func (f *fakeMongoAdaptor) InsertAll(ctx context.Context, name string, docs ...any) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) Update(ctx context.Context, name string, query, update any, multi bool) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) UpdateById(ctx context.Context, name string, id, update any) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) UpdateRaw(ctx context.Context, name string, query, update any, multi bool, upsert ...bool) error {
	return errUnsupportedMongo
}
func (f *fakeMongoAdaptor) GetNextSequence(ctx context.Context, name string) (int32, error) {
	return 0, errUnsupportedMongo
}
func (f *fakeMongoAdaptor) FindWithDistinct(ctx context.Context, name, distinct string, query any) ([]any, error) {
	return nil, errUnsupportedMongo
}

func (f *fakeMongoAdaptor) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.docs[name])
}

func TestBuildFlowInstanceKeysUsesCacheKey(t *testing.T) {
	fr := FlowRule{ID: "flow-mixed"}
	fr.Detection.CacheKey = map[string][]string{
		"winlog-0104-0001": {
			"TargetDomainName|domain",
			"TargetUserName|lower|trim",
		},
		"pktlog-0200-0001": {
			"Domain|domain",
			"UserName|lower|trim",
		},
	}
	rs := &Ruleset{FlowRuleByID: map[string]*FlowRule{fr.ID: &fr}}

	keys := rs.BuildFlowInstanceKeys(fr.ID, "winlog-0104-0001", map[string]string{
		"TargetDomainName": "EXAMPLE",
		"TargetUserName":   " Alice ",
	}, "dc01.example.com", "legacy-id")
	if len(keys) != 1 {
		t.Fatalf("expected one cache key, got %v", keys)
	}
	if keys[0] == "legacy-id" {
		t.Fatalf("expected flow cache key, got legacy unique_id")
	}

	keys2 := rs.BuildFlowInstanceKeys(fr.ID, "winlog-0104-0001", map[string]string{
		"TargetDomainName": "example.com",
		"TargetUserName":   "alice",
	}, "dc01.example.com", "legacy-id")
	if len(keys2) != 1 || keys2[0] != keys[0] {
		t.Fatalf("expected normalized keys to match, got %v and %v", keys, keys2)
	}

	pktKeys := rs.BuildFlowInstanceKeys(fr.ID, "pktlog-0200-0001", map[string]string{
		"Domain":   "example.com",
		"UserName": "alice",
	}, "dc01.example.com", "legacy-id")
	if len(pktKeys) != 1 || pktKeys[0] != keys[0] {
		t.Fatalf("expected pktlog key to match winlog key, got %v and %v", pktKeys, keys)
	}
}

func TestExtractFieldsIncludesDynamicCacheKeyParams(t *testing.T) {
	conditions := parseMatchByExpression("$s1.TargetUserName in $v.cache.key_ada:engine:%s:sensitive_users($s1.TargetDomainName)")
	fields := extractFields(conditions, []string{"winlog-0104-0001"})
	got := fields["winlog-0104-0001"]

	for _, want := range []string{"TargetUserName", "TargetDomainName"} {
		if !slices.Contains(got, want) {
			t.Fatalf("expected extracted fields to include %s, got %v", want, got)
		}
	}
}

func TestParseConditionKeepsLongOperators(t *testing.T) {
	c := parseCondition("$s1.Count >= $s2.MinCount")
	if !c.valid {
		t.Fatalf("expected condition to be valid")
	}
	if c.operation != ">=" {
		t.Fatalf("expected >= operator, got %q", c.operation)
	}
}

func TestMatchExpressionSupportsOrParenthesesAndNot(t *testing.T) {
	expr, conditions, err := parseMatchExpression("($s1.UserName == admin OR $s2.UserName == bob) AND NOT ($s1.TargetDomainName == blocked)")
	if err != nil {
		t.Fatal(err)
	}
	if len(conditions) != 3 {
		t.Fatalf("expected 3 leaf conditions, got %d", len(conditions))
	}

	rs := &Ruleset{}
	act1 := flowActivity{activityCache: map[string]string{
		"field_UserName":         "alice",
		"field_TargetDomainName": "example.com",
	}}
	act2 := flowActivity{activityCache: map[string]string{
		"field_UserName": "bob",
	}}
	if !rs.matchExpr(context.Background(), expr, act1, act2) {
		t.Fatalf("expected expression to match")
	}

	act1.activityCache["field_TargetDomainName"] = "blocked"
	if rs.matchExpr(context.Background(), expr, act1, act2) {
		t.Fatalf("expected NOT branch to reject blocked domain")
	}
}

func TestCountExpressionSupportsComparatorsLenAndDistinct(t *testing.T) {
	activities := []flowActivity{
		{activityCache: map[string]string{"sid": "winlog-0001", "field_TargetUserName": "Alice"}},
		{activityCache: map[string]string{"sid": "winlog-0001", "field_TargetUserName": "alice"}},
		{activityCache: map[string]string{"sid": "winlog-0001", "field_TargetUserName": "Bob"}},
	}
	sigmaIDs := []string{"winlog-0001"}

	cases := []string{
		"$s1._count >= 3",
		"len($s1) >= 3",
		"len(distinct($s1.TargetUserName)) == 2",
		"$s1.TargetUserName._count >= 2",
	}

	for _, expression := range cases {
		countExpr, err := parseCountExpression(expression)
		if err != nil {
			t.Fatalf("parse %s: %v", expression, err)
		}
		if !compareInt(countExpr.operation, countExpr.count(activities, sigmaIDs), countExpr.threshold) {
			t.Fatalf("expected count expression to match: %s", expression)
		}
	}
}

func TestLDAPLookupUsesRedisCacheAndPublishesMiss(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	ctx := context.Background()
	template := "key_ada:engine:%s:sensitive_users($s1.TargetDomainName)"
	acts := []flowActivity{
		{activityCache: map[string]string{
			"field_TargetDomainName": "example.com",
		}},
	}
	cacheKey := "ada:engine:example.com:sensitive_users"

	if err := rdb.SAdd(ctx, cacheKey, "alice").Err(); err != nil {
		t.Fatal(err)
	}
	if vals := getFieldLDAPVal(ctx, rdb, template, acts); len(vals) != 1 || vals[0] != "alice" {
		t.Fatalf("expected cached LDAP value, got %v", vals)
	}

	if err := rdb.Del(ctx, cacheKey).Err(); err != nil {
		t.Fatal(err)
	}
	pubsub := rdb.Subscribe(ctx, common.LdapSearchPubsubChan)
	t.Cleanup(func() { _ = pubsub.Close() })
	if _, err := pubsub.Receive(ctx); err != nil {
		t.Fatal(err)
	}

	if vals := getFieldLDAPVal(ctx, rdb, template, acts); len(vals) != 0 {
		t.Fatalf("expected empty values on cache miss, got %v", vals)
	}
	if exists := rdb.Exists(ctx, ldapPendingKey(cacheKey)).Val(); exists != 1 {
		t.Fatalf("expected LDAP pending key to be set")
	}

	msgCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	msg, err := pubsub.ReceiveMessage(msgCtx)
	if err != nil {
		t.Fatal(err)
	}
	var req ldapLookupRequest
	if err := json.Unmarshal([]byte(msg.Payload), &req); err != nil {
		t.Fatal(err)
	}
	if req.CacheKey != cacheKey || req.CacheTTLSeconds != common.LdapSearchCacheTTLSeconds {
		t.Fatalf("unexpected LDAP request payload: %#v", req)
	}
}

func TestNewRuleListDefaultsEnableAndRejectsInvalidIndex(t *testing.T) {
	dir := t.TempDir()
	validPath := filepath.Join(dir, "valid.yml")
	invalidPath := filepath.Join(dir, "invalid.yml")

	validRule := `title: Mixed Rule
id: flow-mixed
status: experimental
description: test
references: []
author: test
date: 2026/05/03
modified: 2026/05/03
tags:
  - TA0007
logsource: flow
detection:
  event_type: multi_eve_pkt
  win_size: 60s
  sorted: false
  sigma_rules:
    - "winlog-0104-0001"
    - "pktlog-0200-0001"
  cache_key:
    winlog-0104-0001:
      - "TargetDomainName|domain"
      - "TargetUserName|lower"
    pktlog-0200-0001:
      - "Domain|domain"
      - "UserName|lower"
  match_by: "$s1.TargetUserName == $s2.UserName"
level: medium
`
	invalidRule := `title: Invalid Rule
id: flow-invalid
status: experimental
description: test
references: []
author: test
date: 2026/05/03
modified: 2026/05/03
tags:
  - TA0007
logsource: flow
detection:
  event_type: multi_eve
  win_size: 60s
  sigma_rules:
    - "winlog-0104-0001"
  match_by: "$s2.TargetUserName == admin"
level: medium
`
	if err := os.WriteFile(validPath, []byte(validRule), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidPath, []byte(invalidRule), 0o644); err != nil {
		t.Fatal(err)
	}

	rules, err := NewRuleList([]string{validPath, invalidPath})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected only valid rule to load, got %d", len(rules))
	}
	if rules[0].ID != "flow-mixed" {
		t.Fatalf("expected flow-mixed, got %s", rules[0].ID)
	}
	if !rules[0].Enable {
		t.Fatalf("expected omitted enable field to default true")
	}
}

func TestMatchEventMultiEvePktStoresEvent(t *testing.T) {
	s := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: s.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	mongoCli := newFakeMongoAdaptor()
	var _ mongo.DBAdaptor = mongoCli

	fr := FlowRule{
		Title:       "Mixed Winlog Pktlog",
		ID:          "flow-mixed",
		Status:      "experimental",
		Description: "mixed flow",
		Tags:        []string{"TA0007"},
		Level:       "medium",
	}
	fr.Detection.EventType = common.EventTypeMultiEvePkt
	fr.Detection.WinSizeTs = 60
	fr.Detection.SigmaRules = []string{"winlog-0104-0001", "pktlog-0200-0001"}
	fr.Detection.MatchBy = "$s1.TargetUserName == $s2.UserName AND $s1.TargetDomainName == $s2.Domain"

	rs := &Ruleset{
		redisCli:     rdb,
		mongoCli:     mongoCli,
		FlowRules:    []FlowRule{fr},
		FlowRuleByID: map[string]*FlowRule{fr.ID: &fr},
	}

	ctx := context.Background()
	now := time.Now().UnixMilli()
	instanceID := fmt.Sprintf("%s:%s_%s", common.FlowInstancePrefixKey, fr.ID, "cachekey")

	if err := rdb.HSet(ctx, "activity:1", map[string]any{
		"mid":                    "m1",
		"sid":                    "winlog-0104-0001",
		"dc_hostname":            "dc01.example.com",
		"field_TargetUserName":   "alice",
		"field_TargetDomainName": "example.com",
	}).Err(); err != nil {
		t.Fatal(err)
	}
	if err := rdb.HSet(ctx, "activity:2", map[string]any{
		"mid":            "m2",
		"sid":            "pktlog-0200-0001",
		"dc_hostname":    "dc01.example.com",
		"field_UserName": "alice",
		"field_Domain":   "example.com",
	}).Err(); err != nil {
		t.Fatal(err)
	}
	if err := rdb.ZAdd(ctx, instanceID,
		redis.Z{Score: float64(now - 1000), Member: "activity:1"},
		redis.Z{Score: float64(now - 500), Member: "activity:2"},
	).Err(); err != nil {
		t.Fatal(err)
	}

	rs.matchEventMultiEvePkt(ctx, fr, []string{instanceID})

	if got := mongoCli.count("tb_alert_event"); got != 1 {
		t.Fatalf("expected one alert event, got %d", got)
	}
	if got := rdb.LLen(ctx, common.AlertNotifyQueueKey).Val(); got != 1 {
		t.Fatalf("expected one notify message, got %d", got)
	}
	if exists := rdb.Exists(ctx, instanceID).Val(); exists != 0 {
		t.Fatalf("expected matched instance to be deleted, exists=%d", exists)
	}
}
