package main

import (
	"ada/backend/model"
	"ada/infra/mongo"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
	"gopkg.in/yaml.v3"
)

const defaultMongoURI = "mongodb://user_ada:XEl44B4p3hFurztFMo38@192.168.7.2:27017/db_ada?authSource=db_ada"

type FlexibleLogsource map[string]any

func (l *FlexibleLogsource) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		*l = FlexibleLogsource{"product": value.Value}
		return nil
	}

	var raw map[string]any
	if err := value.Decode(&raw); err != nil {
		return err
	}
	*l = FlexibleLogsource(raw)
	return nil
}

func (l FlexibleLogsource) String(defaultRuleType string) string {
	if l == nil {
		return defaultRuleType
	}
	product, _ := l["product"].(string)
	product = strings.ToLower(product)
	switch product {
	case "", "sigma_flow", "flow":
		return defaultRuleType
	case "windows", "winlog":
		return "winlog"
	case "pktlog":
		return "pktlog"
	default:
		return product
	}
}

type EngineRule struct {
	Title         string            `yaml:"title"`
	ID            string            `yaml:"id"`
	Status        string            `yaml:"status"`
	Enable        *bool             `yaml:"enable"`
	Description   string            `yaml:"description"`
	References    []string          `yaml:"references"`
	Author        string            `yaml:"author"`
	Date          string            `yaml:"date"`
	Modified      string            `yaml:"modified"`
	Tags          []string          `yaml:"tags"`
	Logsource     FlexibleLogsource `yaml:"logsource"`
	Detection     map[string]any    `yaml:"detection"`
	Fields        []string          `yaml:"fields"`
	UniqueFields  []string          `yaml:"unique_fields"`
	RdxKey        string            `yaml:"rdx_key"`
	Level         any               `yaml:"level"`
	Type          string            `yaml:"type"`
	RuleOrigin    string            `yaml:"rule_origin"`
	Suggestion    string            `yaml:"suggestion"`
	AutoBlock     bool              `yaml:"auto_block"`
	AttackFlow    model.AttackFlow  `yaml:"attack_flow"`
	UniqueFilter  []string          `yaml:"unique_filter"`
	XSourceRepo   string            `yaml:"x_source_repository"`
	XSourceFile   string            `yaml:"x_source_file"`
	XSourceCommit string            `yaml:"x_source_commit"`
}

type importResult struct {
	flow     int
	winlog   int
	pktlog   int
	deletedF int
	deletedA int
}

func main() {
	var rulesDir, mongoURI string
	var deleteMissing, dryRun bool
	flag.StringVar(&rulesDir, "rules", "/home/adadmin/rules", "engine rules directory")
	flag.StringVar(&mongoURI, "mongo-uri", defaultMongoURI, "MongoDB URI")
	flag.BoolVar(&deleteMissing, "delete-missing", true, "delete backend rules that are absent from engine rules")
	flag.BoolVar(&dryRun, "dry-run", false, "parse rules and print the planned changes without writing MongoDB")
	flag.Parse()

	ctx := context.Background()
	cli, err := connectMongo(ctx, mongoURI)
	if err != nil {
		fatal(err)
	}
	defer cli.Disconnect(ctx)

	result, err := importRules(ctx, cli, rulesDir, deleteMissing, dryRun)
	if err != nil {
		fatal(err)
	}

	mode := "updated"
	if dryRun {
		mode = "validated"
	}
	fmt.Printf("%s rules: flow=%d winlog=%d pktlog=%d deleted_flow=%d deleted_activity=%d\n",
		mode, result.flow, result.winlog, result.pktlog, result.deletedF, result.deletedA)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func connectMongo(ctx context.Context, uri string) (*mongo.MongoSession, error) {
	cs, err := connstring.Parse(uri)
	if err != nil {
		return nil, err
	}
	if cs.Database == "" {
		return nil, fmt.Errorf("MongoDB URI must include database name")
	}

	cli := mongo.NewMongoSession()
	if err := cli.Connect(ctx, uri, cs.Database); err != nil {
		return nil, err
	}
	return cli, nil
}

func importRules(ctx context.Context, cli mongo.DBAdaptor, rulesDir string, deleteMissing, dryRun bool) (importResult, error) {
	activityRules, activityType, err := parseActivityRules(rulesDir)
	if err != nil {
		return importResult{}, err
	}
	flowRules, err := parseFlowRules(rulesDir, activityRules)
	if err != nil {
		return importResult{}, err
	}

	result := importResult{}
	if dryRun {
		for _, rule := range flowRules {
			result.flow++
			_ = rule
		}
		for _, rule := range activityRules {
			if activityType[rule.ID] == "pktlog" {
				result.pktlog++
			} else {
				result.winlog++
			}
		}
		return result, nil
	}

	flowIDs := make(map[string]bool, len(flowRules))
	for _, rule := range flowRules {
		if err := upsertAlertRule(ctx, cli, rule); err != nil {
			return result, err
		}
		flowIDs[rule.ID] = true
		result.flow++
	}

	activityIDs := make(map[string]bool, len(activityRules))
	for _, rule := range activityRules {
		if err := upsertActivityRule(ctx, cli, rule); err != nil {
			return result, err
		}
		activityIDs[rule.ID] = true
		if activityType[rule.ID] == "pktlog" {
			result.pktlog++
		} else {
			result.winlog++
		}
	}

	if deleteMissing {
		deletedF, err := deleteMissingAlertRules(ctx, cli, flowIDs)
		if err != nil {
			return result, err
		}
		deletedA, err := deleteMissingActivityRules(ctx, cli, activityIDs)
		if err != nil {
			return result, err
		}
		result.deletedF = deletedF
		result.deletedA = deletedA
	}

	return result, nil
}

func parseActivityRules(rulesDir string) (map[string]*model.AlertActivityRule, map[string]string, error) {
	out := make(map[string]*model.AlertActivityRule)
	ruleTypes := make(map[string]string)
	for _, ruleType := range []string{"winlog", "pktlog"} {
		files, err := listRuleFiles(filepath.Join(rulesDir, ruleType))
		if err != nil {
			return nil, nil, err
		}
		for _, file := range files {
			raw, err := parseEngineRule(file)
			if err != nil {
				return nil, nil, err
			}
			if raw.ID == "" {
				return nil, nil, fmt.Errorf("missing id in %s", file)
			}
			createTm := parseRuleDate(raw.Date)
			updateTm := parseRuleDate(raw.Modified)
			if updateTm.IsZero() {
				updateTm = createTm
			}

			rule := &model.AlertActivityRule{
				ID:           raw.ID,
				Title:        raw.Title,
				Description:  raw.Description,
				Level:        levelToInt(raw.Level),
				Status:       defaultString(raw.Status, "experimental"),
				Tags:         raw.Tags,
				Logsource:    raw.Logsource.String(ruleType),
				RuleOrigin:   inferRuleOrigin(raw),
				References:   raw.References,
				Detection:    normalizeDetection(raw.Detection),
				RdxKey:       raw.RdxKey,
				Fields:       normalizeStringSlice(raw.Fields),
				UniqueFields: normalizeStringSlice(raw.UniqueFields),
				Author:       raw.Author,
				CreateTm:     createTm,
				UpdateTm:     updateTm,
			}
			out[rule.ID] = rule
			ruleTypes[rule.ID] = ruleType
		}
	}
	return out, ruleTypes, nil
}

func parseFlowRules(rulesDir string, activityRules map[string]*model.AlertActivityRule) ([]*model.AlertRule, error) {
	files, err := listRuleFiles(filepath.Join(rulesDir, "flow"))
	if err != nil {
		return nil, err
	}

	rules := make([]*model.AlertRule, 0, len(files))
	for _, file := range files {
		raw, err := parseEngineRule(file)
		if err != nil {
			return nil, err
		}
		if raw.ID == "" {
			return nil, fmt.Errorf("missing id in %s", file)
		}

		createTm := parseRuleDate(raw.Date)
		updateTm := parseRuleDate(raw.Modified)
		if updateTm.IsZero() {
			updateTm = createTm
		}
		enable := true
		if raw.Enable != nil {
			enable = *raw.Enable
		}

		rule := &model.AlertRule{
			ID:          raw.ID,
			Title:       raw.Title,
			Description: raw.Description,
			Enable:      enable,
			Level:       levelToInt(raw.Level),
			Status:      defaultString(raw.Status, "experimental"),
			Tags:        raw.Tags,
			Logsource:   "flow",
			RuleOrigin:  inferRuleOrigin(raw),
			Detection: model.AlertDetection{
				EventType:  getString(raw.Detection, "event_type"),
				WinSize:    getString(raw.Detection, "win_size"),
				Sorted:     getBool(raw.Detection, "sorted"),
				SigmaRules: getSigmaIDs(raw.Detection),
				MatchBy:    getMatchBy(raw.Detection),
			},
			Type:         inferRuleType(raw),
			References:   raw.References,
			Suggestion:   raw.Suggestion,
			Author:       raw.Author,
			AutoBlock:    raw.AutoBlock,
			AttackFlow:   raw.AttackFlow,
			UniqueFilter: normalizeStringSlice(raw.UniqueFilter),
			CreateTm:     createTm,
			UpdateTm:     updateTm,
		}
		if isEmptyAttackFlow(rule.AttackFlow) {
			rule.AttackFlow = inferAttackFlow(rule, activityRules)
		}
		rules = append(rules, rule)
	}

	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules, nil
}

func listRuleFiles(dir string) ([]string, error) {
	var files []string
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return files, nil
	}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(entry.Name()))
		if ext == ".yml" || ext == ".yaml" {
			files = append(files, path)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	sort.Strings(files)
	return files, nil
}

func parseEngineRule(path string) (EngineRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return EngineRule{}, err
	}
	var rule EngineRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return EngineRule{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return rule, nil
}

func upsertAlertRule(ctx context.Context, cli mongo.DBAdaptor, rule *model.AlertRule) error {
	update := bson.M{
		"title":         rule.Title,
		"description":   rule.Description,
		"enable":        rule.Enable,
		"level":         rule.Level,
		"status":        rule.Status,
		"tags":          rule.Tags,
		"logsource":     rule.Logsource,
		"rule_origin":   rule.RuleOrigin,
		"detection":     rule.Detection,
		"type":          rule.Type,
		"references":    rule.References,
		"suggestion":    rule.Suggestion,
		"author":        rule.Author,
		"auto_block":    rule.AutoBlock,
		"attack_flow":   rule.AttackFlow,
		"unique_filter": rule.UniqueFilter,
		"create_tm":     rule.CreateTm,
		"update_tm":     rule.UpdateTm,
	}
	return cli.UpdateRaw(ctx, rule.CollectName(), bson.M{"_id": rule.ID}, bson.M{
		"$set":         update,
		"$setOnInsert": bson.M{"_id": rule.ID},
	}, false, true)
}

func upsertActivityRule(ctx context.Context, cli mongo.DBAdaptor, rule *model.AlertActivityRule) error {
	update := bson.M{
		"title":         rule.Title,
		"description":   rule.Description,
		"level":         rule.Level,
		"status":        rule.Status,
		"tags":          rule.Tags,
		"logsource":     rule.Logsource,
		"rule_origin":   rule.RuleOrigin,
		"references":    rule.References,
		"detection":     rule.Detection,
		"rdx_key":       rule.RdxKey,
		"fields":        rule.Fields,
		"unique_fields": rule.UniqueFields,
		"author":        rule.Author,
		"create_tm":     rule.CreateTm,
		"update_tm":     rule.UpdateTm,
	}
	return cli.UpdateRaw(ctx, rule.CollectName(), bson.M{"_id": rule.ID}, bson.M{
		"$set":         update,
		"$setOnInsert": bson.M{"_id": rule.ID},
	}, false, true)
}

func deleteMissingAlertRules(ctx context.Context, cli mongo.DBAdaptor, keep map[string]bool) (int, error) {
	var existing []model.AlertRule
	if err := cli.FindAll(ctx, (&model.AlertRule{}).CollectName(), bson.M{}, &existing); err != nil {
		return 0, err
	}
	deleted := 0
	for _, rule := range existing {
		if keep[rule.ID] {
			continue
		}
		if err := cli.RemoveById(ctx, rule.CollectName(), rule.ID); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func deleteMissingActivityRules(ctx context.Context, cli mongo.DBAdaptor, keep map[string]bool) (int, error) {
	var existing []model.AlertActivityRule
	if err := cli.FindAll(ctx, (&model.AlertActivityRule{}).CollectName(), bson.M{}, &existing); err != nil {
		return 0, err
	}
	deleted := 0
	for _, rule := range existing {
		if keep[rule.ID] {
			continue
		}
		if err := cli.RemoveById(ctx, rule.CollectName(), rule.ID); err != nil {
			return deleted, err
		}
		deleted++
	}
	return deleted, nil
}

func levelToInt(level any) int32 {
	switch v := level.(type) {
	case int:
		return int32(v)
	case int32:
		return v
	case int64:
		return int32(v)
	case float64:
		return int32(v)
	case string:
		if n, err := strconv.Atoi(v); err == nil {
			return int32(n)
		}
		switch strings.ToLower(v) {
		case "info", "informational":
			return 1
		case "low":
			return 2
		case "medium":
			return 3
		case "high":
			return 4
		case "critical":
			return 5
		}
	}
	return 3
}

func parseRuleDate(dateStr string) time.Time {
	if dateStr == "" {
		return time.Now()
	}
	for _, layout := range []string{"2006/01/02", "2006-01-02", "2006/01/02 15:04:05", "2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, dateStr); err == nil {
			return t
		}
	}
	return time.Now()
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func normalizeDetection(in map[string]any) model.ActivityDetection {
	if in == nil {
		return model.ActivityDetection{}
	}
	data, err := json.Marshal(in)
	if err != nil {
		return model.ActivityDetection(in)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		return model.ActivityDetection(in)
	}
	return model.ActivityDetection(out)
}

func normalizeStringSlice(in []string) []string {
	if in == nil {
		return []string{}
	}
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, item := range in {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if value, ok := m[key]; ok {
		switch v := value.(type) {
		case string:
			return v
		case fmt.Stringer:
			return v.String()
		default:
			return fmt.Sprint(v)
		}
	}
	return ""
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	value, ok := m[key]
	if !ok {
		return false
	}
	if b, ok := value.(bool); ok {
		return b
	}
	return false
}

func getSigmaIDs(detection map[string]any) []string {
	if ids := toStringSliceAny(detection["sigma_rules"]); len(ids) > 0 {
		return ids
	}
	if selection, ok := detection["selection"].(map[string]any); ok {
		return toStringSliceAny(selection["sigma_id"])
	}
	return []string{}
}

func getMatchBy(detection map[string]any) string {
	if matchBy := getString(detection, "match_by"); matchBy != "" {
		return matchBy
	}
	if selection, ok := detection["selection"].(map[string]any); ok {
		return getString(selection, "match_by")
	}
	return ""
}

func toStringSliceAny(value any) []string {
	switch v := value.(type) {
	case []string:
		return normalizeStringSlice(v)
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return normalizeStringSlice(out)
	case string:
		return []string{v}
	default:
		return []string{}
	}
}

func inferRuleType(rule EngineRule) string {
	if rule.Type != "" {
		return strings.ToLower(rule.Type)
	}
	taMap := map[string]string{
		"TA0001": "initialaccess",
		"TA0002": "execution",
		"TA0003": "persistence",
		"TA0004": "privilegeescalation",
		"TA0005": "defenseevasion",
		"TA0006": "credentialaccess",
		"TA0007": "discovery",
		"TA0008": "lateralmovement",
		"TA0009": "collection",
		"TA0010": "commandcontrol",
		"TA0011": "exfiltration",
		"TA0012": "impact",
	}
	for _, tag := range rule.Tags {
		tag = strings.ToUpper(strings.TrimSpace(tag))
		if v, ok := taMap[tag]; ok {
			return v
		}
	}
	return "execution"
}

func inferRuleOrigin(rule EngineRule) string {
	origin := strings.ToLower(strings.TrimSpace(rule.RuleOrigin))
	switch origin {
	case "internal", "public", "custom":
		return origin
	}
	if rule.XSourceRepo != "" || rule.XSourceFile != "" || rule.XSourceCommit != "" {
		return "public"
	}
	return "internal"
}

func isEmptyAttackFlow(flow model.AttackFlow) bool {
	return flow.Desc == "" && len(flow.Fields) == 0 && len(flow.Relates) == 0
}

func inferAttackFlow(rule *model.AlertRule, activityRules map[string]*model.AlertActivityRule) model.AttackFlow {
	candidates := collectFlowFieldCandidates(rule, activityRules)

	user := pickField(candidates, []string{"TargetUserName", "SubjectUserName", "UserName", "AccountName", "SamAccountName", "MemberName", "User"})
	ip := pickField(candidates, []string{"IpAddress", "SourceIp", "SourceIPAddress", "SourceAddress", "ClientAddress", "WorkstationIp", "RemoteAddress"})
	target := pickField(candidates, []string{"Hostname", "TargetHostName", "ComputerName", "TargetComputerName", "DestinationHostname", "TargetServerName", "ObjectName", "ShareName", "TargetDomainName", "ServiceName", "ProcessName"})

	fields := make([]model.FieldObj, 0, 3)
	addField := func(key string) {
		if key == "" || containsField(fields, key) {
			return
		}
		fields = append(fields, model.FieldObj{Obj: inferFieldObj(key), Key: key})
	}
	addField(user)
	addField(ip)
	addField(target)
	for _, key := range candidates {
		if len(fields) >= 3 {
			break
		}
		addField(key)
	}

	relates := []string{}
	if len(fields) >= 2 {
		relates = append(relates, "来自")
	}
	if len(fields) >= 3 {
		relates = append(relates, "访问")
	}

	desc := rule.Description
	if len(fields) >= 3 {
		desc = fmt.Sprintf("检测到 [%s] 从 [%s] 对 [%s] 触发：%s", fields[0].Key, fields[1].Key, fields[2].Key, rule.Title)
	} else if len(fields) == 2 {
		desc = fmt.Sprintf("检测到 [%s] 与 [%s] 触发：%s", fields[0].Key, fields[1].Key, rule.Title)
	} else if desc == "" {
		desc = rule.Title
	}

	return model.AttackFlow{Desc: desc, Fields: fields, Relates: relates}
}

func collectFlowFieldCandidates(rule *model.AlertRule, activityRules map[string]*model.AlertActivityRule) []string {
	ordered := []string{}
	add := func(field string) {
		field = normalizeFieldName(field)
		if field == "" || strings.HasPrefix(field, "_") || strings.HasPrefix(field, "ttl_") {
			return
		}
		if _, err := strconv.Atoi(field); err == nil {
			return
		}
		for _, item := range ordered {
			if item == field {
				return
			}
		}
		ordered = append(ordered, field)
	}

	for _, sigmaID := range rule.Detection.SigmaRules {
		if activity := activityRules[sigmaID]; activity != nil {
			for _, field := range activity.Fields {
				add(field)
			}
			for _, field := range activity.UniqueFields {
				add(field)
			}
		}
	}
	for _, field := range extractRefs(rule.Detection.MatchBy) {
		add(field)
	}
	for _, field := range rule.UniqueFilter {
		add(field)
	}

	return ordered
}

var fieldRefRe = regexp.MustCompile(`\$s\d+\.([A-Za-z_][A-Za-z0-9_]*)`)

func extractRefs(expr string) []string {
	matches := fieldRefRe.FindAllStringSubmatch(expr, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			out = append(out, match[1])
		}
	}
	return out
}

func normalizeFieldName(field string) string {
	field = strings.TrimSpace(field)
	field = strings.TrimPrefix(field, "field_")
	if strings.HasPrefix(field, "$s") {
		if idx := strings.Index(field, "."); idx >= 0 && idx+1 < len(field) {
			field = field[idx+1:]
		}
	}
	field = strings.TrimPrefix(field, "field_")
	if strings.Contains(field, ".") {
		parts := strings.Split(field, ".")
		field = parts[0]
	}
	return field
}

func pickField(candidates, preferred []string) string {
	for _, want := range preferred {
		for _, candidate := range candidates {
			if strings.EqualFold(candidate, want) {
				return candidate
			}
		}
	}
	for _, candidate := range candidates {
		low := strings.ToLower(candidate)
		for _, want := range preferred {
			if strings.Contains(low, strings.ToLower(want)) {
				return candidate
			}
		}
	}
	return ""
}

func containsField(fields []model.FieldObj, key string) bool {
	for _, field := range fields {
		if field.Key == key {
			return true
		}
	}
	return false
}

func inferFieldObj(key string) string {
	low := strings.ToLower(key)
	switch {
	case strings.Contains(low, "ip") || strings.Contains(low, "address"):
		return "ip"
	case strings.Contains(low, "user") || strings.Contains(low, "account") || strings.Contains(low, "sid") || strings.Contains(low, "member"):
		return "user"
	case strings.Contains(low, "domain") || strings.Contains(low, "dc"):
		return "dc"
	default:
		return "computer"
	}
}
