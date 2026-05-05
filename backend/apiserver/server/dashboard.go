package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	"regexp"
	"sort"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type AlertTrendByMonth struct {
	Labels                  []string
	Total                   []int32
	High                    []int32
	Medium                  []int32
	Low                     []int32
	AlertPending            []int32
	AlertHandled            []int32
	AlertWhitelisted        []int32
	AlertBlocked            []int32
	DomainRiskDomains       []string
	DomainRiskHighAlerts    []int32
	DomainRiskHighLeaks     []int32
	DomainRiskHighBaselines []int32
	ScanLeakFinished        []int32
	ScanLeakFailed          []int32
	ScanLeakHits            []int32
	ScanBaselineFinished    []int32
	ScanBaselineFailed      []int32
	ScanBaselineHits        []int32
	ScanWeakpwdFinished     []int32
	ScanWeakpwdFailed       []int32
	ScanWeakpwdHits         []int32
}

// GetAlertCountsByLevel returns alert counts grouped by level
func GetAlertCountsByLevel(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)
	tb := (&model.AlertEventESDB{}).CollectName()

	// Query for unprocessed alerts (event_status = 0)
	query := bson.D{
		{Key: "event_status", Value: 0},
	}

	// Filter by domains if specified
	if len(domains) > 0 {
		query = append(query, bson.E{Key: "dc_hostname", Value: bson.D{{Key: "$in", Value: domains}}})
	}

	// Get all alert events
	var alerts []model.AlertEventESDB
	err := e.MongoCli.FindAll(e.MongoContext(), tb, query, &alerts)
	if err != nil {
		logger.Errorf("find alert events err:%v", err)
		return result, err
	}

	// Count by level
	levelCounts := make(map[int32]int32)
	for _, alert := range alerts {
		levelCounts[alert.Level]++
	}

	// Convert to string keys: "high"=2, "medium"=3, "low"=4/5
	for level, count := range levelCounts {
		switch level {
		case 2:
			result["high"] = count
		case 3:
			result["medium"] = count
		case 4, 5:
			result["low"] += count
		}
	}

	return result, nil
}

// GetAlertTrendByMonth returns monthly alert event counts for the selected year.
func GetAlertTrendByMonth(e *config.Env, domains []string, year int) (*AlertTrendByMonth, error) {
	tb := (&model.AlertEventESDB{}).CollectName()
	if year <= 0 {
		year = time.Now().Year()
	}

	start := time.Date(year, time.January, 1, 0, 0, 0, 0, time.Local)
	end := start.AddDate(1, 0, 0)
	startMs := start.UnixMilli()
	endMs := end.UnixMilli()

	queryParts := bson.A{
		bson.M{"$or": bson.A{
			bson.M{"end_ts": bson.M{"$gte": startMs, "$lt": endMs}},
			bson.M{"create_tm": bson.M{"$gte": start, "$lt": end}},
		}},
	}
	if len(domains) > 0 {
		domainFilters := make(bson.A, 0, len(domains))
		for _, domain := range domains {
			if domain == "" {
				continue
			}
			domainFilters = append(domainFilters, bson.M{
				"dc_hostname": bson.M{
					"$regex": bson.Regex{Pattern: ".*" + regexp.QuoteMeta(domain) + "$", Options: "i"},
				},
			})
		}
		if len(domainFilters) > 0 {
			queryParts = append(queryParts, bson.M{"$or": domainFilters})
		}
	}

	var query any = bson.M{"$and": queryParts}
	if len(queryParts) == 1 {
		query = queryParts[0]
	}

	var alerts []model.AlertEventESDB
	if err := e.MongoCli.FindAll(e.MongoContext(), tb, query, &alerts); err != nil {
		logger.Errorf("find alert trend events err:%v", err)
		return nil, err
	}

	trend := &AlertTrendByMonth{
		Labels:               make([]string, 12),
		Total:                make([]int32, 12),
		High:                 make([]int32, 12),
		Medium:               make([]int32, 12),
		Low:                  make([]int32, 12),
		AlertPending:         make([]int32, 12),
		AlertHandled:         make([]int32, 12),
		AlertWhitelisted:     make([]int32, 12),
		AlertBlocked:         make([]int32, 12),
		ScanLeakFinished:     make([]int32, 12),
		ScanLeakFailed:       make([]int32, 12),
		ScanLeakHits:         make([]int32, 12),
		ScanBaselineFinished: make([]int32, 12),
		ScanBaselineFailed:   make([]int32, 12),
		ScanBaselineHits:     make([]int32, 12),
		ScanWeakpwdFinished:  make([]int32, 12),
		ScanWeakpwdFailed:    make([]int32, 12),
		ScanWeakpwdHits:      make([]int32, 12),
	}
	for month := 1; month <= 12; month++ {
		trend.Labels[month-1] = time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.Local).Format("2006-01")
	}

	riskByDomain := make(map[string]*domainRisk)
	for _, domain := range domains {
		if domain != "" {
			riskByDomain[domain] = &domainRisk{Domain: domain}
		}
	}

	for _, alert := range alerts {
		alertTime := alert.CreateTm
		switch {
		case alert.EndTs > 0:
			alertTime = time.UnixMilli(alert.EndTs)
		case alert.StartTs > 0:
			alertTime = time.UnixMilli(alert.StartTs)
		}
		if alertTime.Before(start) || !alertTime.Before(end) {
			continue
		}

		monthIdx := int(alertTime.Month()) - 1
		trend.Total[monthIdx]++
		switch alert.Level {
		case 5, 4:
			trend.High[monthIdx]++
			if domain := matchDomain(alert.DcHostname, domains); domain != "" {
				risk := ensureDomainRisk(riskByDomain, domain)
				risk.HighAlerts++
			}
		case 3:
			trend.Medium[monthIdx]++
		case 2:
			trend.Low[monthIdx]++
		}

		switch alert.EventStatus {
		case 0:
			trend.AlertPending[monthIdx]++
		case 1:
			trend.AlertHandled[monthIdx]++
		case 2:
			trend.AlertWhitelisted[monthIdx]++
		case 3:
			trend.AlertBlocked[monthIdx]++
		}
	}

	if err := fillDomainRiskScanCounts(e, domains, riskByDomain); err != nil {
		logger.Errorf("fill domain risk scan counts err:%v", err)
		return nil, err
	}
	fillDomainRiskSeries(trend, riskByDomain)

	if err := fillScanTaskTrend(e, domains, start, end, trend); err != nil {
		logger.Errorf("fill scan task trend err:%v", err)
		return nil, err
	}

	return trend, nil
}

type domainRisk struct {
	Domain        string
	HighAlerts    int32
	HighLeaks     int32
	HighBaselines int32
}

func ensureDomainRisk(risks map[string]*domainRisk, domain string) *domainRisk {
	risk, ok := risks[domain]
	if !ok {
		risk = &domainRisk{Domain: domain}
		risks[domain] = risk
	}
	return risk
}

func matchDomain(hostname string, domains []string) string {
	if hostname == "" {
		return ""
	}
	normalizedHostname := strings.ToLower(hostname)
	for _, domain := range domains {
		normalizedDomain := strings.ToLower(strings.TrimSpace(domain))
		if normalizedDomain == "" {
			continue
		}
		if normalizedHostname == normalizedDomain || strings.HasSuffix(normalizedHostname, "."+normalizedDomain) {
			return domain
		}
	}
	return ""
}

func fillDomainRiskSeries(trend *AlertTrendByMonth, riskByDomain map[string]*domainRisk) {
	risks := make([]*domainRisk, 0, len(riskByDomain))
	for _, risk := range riskByDomain {
		risks = append(risks, risk)
	}
	sort.Slice(risks, func(i, j int) bool {
		left := risks[i].HighAlerts + risks[i].HighLeaks + risks[i].HighBaselines
		right := risks[j].HighAlerts + risks[j].HighLeaks + risks[j].HighBaselines
		if left == right {
			return risks[i].Domain < risks[j].Domain
		}
		return left > right
	})
	if len(risks) > 10 {
		risks = risks[:10]
	}

	for _, risk := range risks {
		trend.DomainRiskDomains = append(trend.DomainRiskDomains, risk.Domain)
		trend.DomainRiskHighAlerts = append(trend.DomainRiskHighAlerts, risk.HighAlerts)
		trend.DomainRiskHighLeaks = append(trend.DomainRiskHighLeaks, risk.HighLeaks)
		trend.DomainRiskHighBaselines = append(trend.DomainRiskHighBaselines, risk.HighBaselines)
	}
}

func fillDomainRiskScanCounts(e *config.Env, domains []string, riskByDomain map[string]*domainRisk) error {
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		risk := ensureDomainRisk(riskByDomain, domain)
		leaks, err := countLatestHighRiskScanHits(e, domain, "leak")
		if err != nil {
			return err
		}
		baselines, err := countLatestHighRiskScanHits(e, domain, "baseline")
		if err != nil {
			return err
		}
		risk.HighLeaks = leaks
		risk.HighBaselines = baselines
	}
	return nil
}

func countLatestHighRiskScanHits(e *config.Env, domain, scanType string) (int32, error) {
	taskQuery := bson.D{
		{Key: "domain", Value: domain},
		{Key: "type", Value: scanType},
		{Key: "status", Value: "FINISH"},
	}

	var tasks []model.ScanTasks
	sortBy := bson.M{"create_tm": -1}
	if err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), (&model.ScanTasks{}).CollectName(), taskQuery, sortBy, &tasks, 1, 0); err != nil {
		return 0, err
	}
	if len(tasks) == 0 {
		return 0, nil
	}

	subtaskQuery := bson.D{
		{Key: "status", Value: "FINISH"},
		{Key: "group_id", Value: tasks[0].ID.Hex()},
		{Key: "params.domain", Value: domain},
		{Key: "result.status", Value: bson.D{{Key: "$gt", Value: 0}}},
		{Key: "result.plugin.risk_level", Value: bson.D{{Key: "$in", Value: []int32{4, 5}}}},
	}
	count, err := e.MongoCli.FindCount(e.MongoContext(), (&model.ScanSubTasks{}).CollectName(), subtaskQuery)
	if err != nil {
		return 0, err
	}
	return int32(count), nil
}

func fillScanTaskTrend(e *config.Env, domains []string, start, end time.Time, trend *AlertTrendByMonth) error {
	query := bson.D{
		{Key: "type", Value: bson.D{{Key: "$in", Value: []string{"leak", "baseline", "weakpwd"}}}},
		{Key: "create_tm", Value: bson.M{"$gte": start, "$lt": end}},
	}
	if len(domains) > 0 {
		query = append(query, bson.E{Key: "domain", Value: bson.D{{Key: "$in", Value: domains}}})
	}

	var tasks []model.ScanTasks
	if err := e.MongoCli.FindAll(e.MongoContext(), (&model.ScanTasks{}).CollectName(), query, &tasks); err != nil {
		return err
	}

	taskIDsByTypeMonth := map[string]map[int][]string{
		"leak":     make(map[int][]string),
		"baseline": make(map[int][]string),
		"weakpwd":  make(map[int][]string),
	}
	for _, task := range tasks {
		if task.CreateTm.Before(start) || !task.CreateTm.Before(end) {
			continue
		}
		monthIdx := int(task.CreateTm.Month()) - 1
		switch task.Type {
		case "leak":
			fillScanTaskStatus(task.Status, monthIdx, trend.ScanLeakFinished, trend.ScanLeakFailed)
			taskIDsByTypeMonth["leak"][monthIdx] = append(taskIDsByTypeMonth["leak"][monthIdx], task.ID.Hex())
		case "baseline":
			fillScanTaskStatus(task.Status, monthIdx, trend.ScanBaselineFinished, trend.ScanBaselineFailed)
			taskIDsByTypeMonth["baseline"][monthIdx] = append(taskIDsByTypeMonth["baseline"][monthIdx], task.ID.Hex())
		case "weakpwd":
			fillScanTaskStatus(task.Status, monthIdx, trend.ScanWeakpwdFinished, trend.ScanWeakpwdFailed)
			taskIDsByTypeMonth["weakpwd"][monthIdx] = append(taskIDsByTypeMonth["weakpwd"][monthIdx], task.ID.Hex())
		}
	}

	for scanType, taskIDsByMonth := range taskIDsByTypeMonth {
		for monthIdx, taskIDs := range taskIDsByMonth {
			hits, err := countScanHitsForTasks(e, taskIDs, scanType)
			if err != nil {
				return err
			}
			switch scanType {
			case "leak":
				trend.ScanLeakHits[monthIdx] += hits
			case "baseline":
				trend.ScanBaselineHits[monthIdx] += hits
			case "weakpwd":
				trend.ScanWeakpwdHits[monthIdx] += hits
			}
		}
	}

	return nil
}

func fillScanTaskStatus(status string, monthIdx int, finished, failed []int32) {
	switch status {
	case "FINISH":
		finished[monthIdx]++
	case "FAILURE":
		failed[monthIdx]++
	}
}

func countScanHitsForTasks(e *config.Env, taskIDs []string, scanType string) (int32, error) {
	if len(taskIDs) == 0 {
		return 0, nil
	}
	query := bson.D{
		{Key: "status", Value: "FINISH"},
		{Key: "group_id", Value: bson.D{{Key: "$in", Value: taskIDs}}},
		{Key: "result.status", Value: bson.D{{Key: "$gt", Value: 0}}},
	}

	if scanType != "weakpwd" {
		count, err := e.MongoCli.FindCount(e.MongoContext(), (&model.ScanSubTasks{}).CollectName(), query)
		if err != nil {
			return 0, err
		}
		return int32(count), nil
	}

	var subtasks []model.ScanSubTasks
	if err := e.MongoCli.FindAll(e.MongoContext(), (&model.ScanSubTasks{}).CollectName(), query, &subtasks); err != nil {
		return 0, err
	}
	var count int32
	for _, task := range subtasks {
		count += countWeakPwdUsers(task.Result.Data["users"])
	}
	return count, nil
}

// GetBaselineCountsByLevel returns baseline issue counts by level from latest scan task
func GetBaselineCountsByLevel(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)

	for _, domain := range domains {
		taskQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "type", Value: "baseline"},
			{Key: "status", Value: "FINISH"},
		}

		var tasks []model.ScanTasks
		sort := bson.M{"create_tm": -1}
		err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), (&model.ScanTasks{}).CollectName(), taskQuery, sort, &tasks, 1, 0)
		if err != nil {
			logger.Errorf("find baseline tasks err:%v", err)
			continue
		}
		if len(tasks) == 0 {
			logger.Debugf("no finished baseline tasks found for domain %s", domain)
			continue
		}

		subtaskQuery := bson.D{
			{Key: "status", Value: "FINISH"},
			{Key: "group_id", Value: tasks[0].ID.Hex()},
			{Key: "params.domain", Value: domain},
			{Key: "result.status", Value: bson.D{{Key: "$gt", Value: 0}}},
		}
		var subtasks []model.ScanSubTasks
		err = e.MongoCli.FindAll(e.MongoContext(), (&model.ScanSubTasks{}).CollectName(), subtaskQuery, &subtasks)
		if err != nil {
			logger.Errorf("find baseline subtasks err:%v", err)
			continue
		}

		for _, task := range subtasks {
			switch task.Result.Plugin.RiskLevel {
			case 2:
				result["high"]++
			case 3:
				result["medium"]++
			case 4, 5:
				result["low"]++
			}
		}
	}

	return result, nil
}

// GetLeakCountsByLevel returns vulnerability counts by level from latest scan task
func GetLeakCountsByLevel(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)

	for _, domain := range domains {
		taskQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "type", Value: "leak"},
			{Key: "status", Value: "FINISH"},
		}

		var tasks []model.ScanTasks
		sort := bson.M{"create_tm": -1}
		err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), (&model.ScanTasks{}).CollectName(), taskQuery, sort, &tasks, 1, 0)
		if err != nil {
			logger.Errorf("find leak tasks err:%v", err)
			continue
		}
		if len(tasks) == 0 {
			logger.Debugf("no finished leak tasks found for domain %s", domain)
			continue
		}

		subtaskQuery := bson.D{
			{Key: "status", Value: "FINISH"},
			{Key: "group_id", Value: tasks[0].ID.Hex()},
			{Key: "params.domain", Value: domain},
			{Key: "result.status", Value: bson.D{{Key: "$gt", Value: 0}}},
		}
		var subtasks []model.ScanSubTasks
		err = e.MongoCli.FindAll(e.MongoContext(), (&model.ScanSubTasks{}).CollectName(), subtaskQuery, &subtasks)
		if err != nil {
			logger.Errorf("find leak subtasks err:%v", err)
			continue
		}

		for _, task := range subtasks {
			switch task.Result.Plugin.RiskLevel {
			case 2:
				result["high"]++
			case 3:
				result["medium"]++
			case 4, 5:
				result["low"]++
			}
		}
	}

	return result, nil
}

// GetWeakPwdCounts returns latest and previous weak password hit counts.
func GetWeakPwdCounts(e *config.Env, domains []string) (int32, int32, error) {
	var latest int32
	var previous int32

	for _, domain := range domains {
		taskQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "type", Value: "weakpwd"},
			{Key: "status", Value: "FINISH"},
		}

		var tasks []model.ScanTasks
		sort := bson.M{"create_tm": -1}
		err := e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), (&model.ScanTasks{}).CollectName(), taskQuery, sort, &tasks, 2, 0)
		if err != nil {
			logger.Errorf("find weakpwd tasks err:%v", err)
			continue
		}
		if len(tasks) == 0 {
			logger.Debugf("no finished weakpwd tasks found for domain %s", domain)
			continue
		}

		count, err := countWeakPwdTaskHits(e, tasks[0].ID.Hex(), domain)
		if err != nil {
			logger.Errorf("count latest weakpwd task hits err:%v", err)
		} else {
			latest += count
		}
		if len(tasks) < 2 {
			continue
		}
		count, err = countWeakPwdTaskHits(e, tasks[1].ID.Hex(), domain)
		if err != nil {
			logger.Errorf("count previous weakpwd task hits err:%v", err)
		} else {
			previous += count
		}
	}

	return latest, previous, nil
}

// GetWeakPwdCount returns total count of weak password detections.
func GetWeakPwdCount(e *config.Env, domains []string) (int32, error) {
	latest, _, err := GetWeakPwdCounts(e, domains)
	return latest, err
}

func countWeakPwdTaskHits(e *config.Env, groupID string, domain string) (int32, error) {
	var count int32

	subtaskQuery := bson.D{
		{Key: "status", Value: "FINISH"},
		{Key: "group_id", Value: groupID},
		{Key: "params.domain", Value: domain},
		{Key: "result.status", Value: bson.D{{Key: "$gt", Value: 0}}},
	}
	var subtasks []model.ScanSubTasks
	err := e.MongoCli.FindAll(e.MongoContext(), (&model.ScanSubTasks{}).CollectName(), subtaskQuery, &subtasks)
	if err != nil {
		return 0, err
	}

	for _, task := range subtasks {
		count += countWeakPwdUsers(task.Result.Data["users"])
	}

	return count, nil
}

func countWeakPwdUsers(users any) int32 {
	switch v := users.(type) {
	case []any:
		return int32(len(v))
	case bson.A:
		return int32(len(v))
	default:
		if users != nil {
			return 1
		}
		return 0
	}
}

// GetAssetCounts returns total asset count and today's new assets
func GetAssetCounts(e *config.Env, domains []string) (int32, int32, error) {
	var total int32
	var today int32

	// Calculate today's start time (00:00:00)
	now := time.Now()
	todayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())

	for _, domain := range domains {
		// Get total assets for this domain (users + computers)
		userQuery := bson.D{{Key: "domain", Value: domain}}
		userCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AssetUser{}).CollectName(), userQuery)
		if err != nil {
			logger.Errorf("find user count err:%v", err)
		} else {
			total += int32(userCount)
		}

		computerQuery := bson.D{{Key: "domain", Value: domain}}
		computerCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AssetComputer{}).CollectName(), computerQuery)
		if err != nil {
			logger.Errorf("find computer count err:%v", err)
		} else {
			total += int32(computerCount)
		}

		// Get today's new assets (created >= today 00:00:00)
		userTodayQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "create_tm", Value: bson.M{"$gte": todayStart}},
		}
		userTodayCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AssetUser{}).CollectName(), userTodayQuery)
		if err != nil {
			logger.Errorf("find today user count err:%v", err)
		} else {
			today += int32(userTodayCount)
		}

		computerTodayQuery := bson.D{
			{Key: "domain", Value: domain},
			{Key: "create_tm", Value: bson.M{"$gte": todayStart}},
		}
		computerTodayCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AssetComputer{}).CollectName(), computerTodayQuery)
		if err != nil {
			logger.Errorf("find today computer count err:%v", err)
		} else {
			today += int32(computerTodayCount)
		}
	}

	return total, today, nil
}

// GetAssetDistribution returns asset distribution counts by type (users, computers, groups)
func GetAssetDistribution(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)

	for _, domain := range domains {
		// Get user count
		userQuery := bson.D{{Key: "domain", Value: domain}}
		userCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AssetUser{}).CollectName(), userQuery)
		if err != nil {
			logger.Errorf("find user count err:%v", err)
		} else {
			result["users"] += int32(userCount)
		}

		// Get computer count
		computerQuery := bson.D{{Key: "domain", Value: domain}}
		computerCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AssetComputer{}).CollectName(), computerQuery)
		if err != nil {
			logger.Errorf("find computer count err:%v", err)
		} else {
			result["computers"] += int32(computerCount)
		}

		// Get group count
		groupQuery := bson.D{{Key: "domain", Value: domain}}
		groupCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AssetGroup{}).CollectName(), groupQuery)
		if err != nil {
			logger.Errorf("find group count err:%v", err)
		} else {
			result["groups"] += int32(groupCount)
		}
	}

	return result, nil
}

// GetRuleDistribution returns rule distribution counts by type (alert rules, activity rules)
func GetRuleDistribution(e *config.Env) (map[string]int32, error) {
	result := make(map[string]int32)

	// Get alert rule count (from tb_alert_rule)
	alertRuleCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AlertRule{}).CollectName(), bson.D{})
	if err != nil {
		logger.Errorf("find alert rule count err:%v", err)
	} else {
		result["alert"] = int32(alertRuleCount)
	}

	// Get activity rule count (from tb_activity_rule)
	activityRuleCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AlertActivityRule{}).CollectName(), bson.D{})
	if err != nil {
		logger.Errorf("find activity rule count err:%v", err)
	} else {
		result["activity"] = int32(activityRuleCount)
	}

	return result, nil
}

// GetAgentDistribution returns agent distribution counts (domains, sensors, dcs)
func GetAgentDistribution(e *config.Env) (map[string]int32, error) {
	result := make(map[string]int32)

	// Get domain count (from tb_domain)
	domainCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.Domain{}).CollectName(), bson.D{})
	if err != nil {
		logger.Errorf("find domain count err:%v", err)
	} else {
		result["domains"] = int32(domainCount)
	}

	// Get sensor count (from tb_sensor)
	sensorCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.Sensor{}).CollectName(), bson.D{})
	if err != nil {
		logger.Errorf("find sensor count err:%v", err)
	} else {
		result["sensors"] = int32(sensorCount)
	}

	// Get DC count by aggregating DCList from all domains
	var domains []model.Domain
	err = e.MongoCli.FindAll(e.MongoContext(), (&model.Domain{}).CollectName(), bson.D{}, &domains)
	if err != nil {
		logger.Errorf("find domains err:%v", err)
	} else {
		dcCount := 0
		for _, domain := range domains {
			dcCount += len(domain.DCList)
		}
		result["dcs"] = int32(dcCount)
	}

	return result, nil
}

// GetEventDistribution returns event distribution counts (alert events, alert activities)
func GetEventDistribution(e *config.Env) (map[string]int32, error) {
	result := make(map[string]int32)

	// Get alert event count (from tb_alert_event)
	eventCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AlertEventESDB{}).CollectName(), bson.D{})
	if err != nil {
		logger.Errorf("find alert event count err:%v", err)
	} else {
		result["events"] = int32(eventCount)
	}

	// Get alert activity count (from tb_alert_activity)
	activityCount, err := e.MongoCli.FindCount(e.MongoContext(), (&model.AlertActivityESDB{}).CollectName(), bson.D{})
	if err != nil {
		logger.Errorf("find alert activity count err:%v", err)
	} else {
		result["activities"] = int32(activityCount)
	}

	return result, nil
}
