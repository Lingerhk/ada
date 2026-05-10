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

type DashboardTrend struct {
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

type trendBucket struct {
	Label string
	Start time.Time
	End   time.Time
}

// GetAlertCountsByLevel uses the same rolling one-day event window as ThreatTops.
func GetAlertCountsByLevel(e *config.Env, domains []string) (map[string]int32, error) {
	result := make(map[string]int32)
	tb := (&model.AlertEventESDB{}).CollectName()

	startTimestamp := threatDurationStartTimestamp(1)
	queryParts := bson.A{
		bson.M{"start_ts": bson.M{"$gte": startTimestamp}},
	}

	if domainFilter, ok := domainHostnameFilter(domains); ok {
		queryParts = append(queryParts, domainFilter)
	}

	query := bson.M{"$and": queryParts}

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

	for level, count := range levelCounts {
		if key, ok := alertLevelKey(level); ok {
			result[key] += count
		}
	}

	return result, nil
}

// GetDashboardTrendByYear returns monthly dashboard trend counts for the selected year.
func GetDashboardTrendByYear(e *config.Env, domains []string, year int) (*DashboardTrend, error) {
	if year <= 0 {
		year = time.Now().Year()
	}

	start := time.Date(year, time.January, 1, 0, 0, 0, 0, time.Local)
	end := start.AddDate(1, 0, 0)
	buckets := make([]trendBucket, 0, 12)
	for month := 1; month <= 12; month++ {
		bucketStart := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.Local)
		buckets = append(buckets, trendBucket{
			Label: bucketStart.Format("2006-01"),
			Start: bucketStart,
			End:   bucketStart.AddDate(0, 1, 0),
		})
	}

	return getDashboardTrend(e, domains, start, end, buckets)
}

// GetDashboardTrendByDuration returns daily dashboard trend counts for the latest N days.
func GetDashboardTrendByDuration(e *config.Env, domains []string, durationDays int) (*DashboardTrend, error) {
	durationDays = normalizeDashboardTrendDurationDays(durationDays)
	now := time.Now()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	start := today.AddDate(0, 0, -durationDays+1)
	end := today.AddDate(0, 0, 1)

	buckets := make([]trendBucket, 0, durationDays)
	for offset := 0; offset < durationDays; offset++ {
		bucketStart := start.AddDate(0, 0, offset)
		buckets = append(buckets, trendBucket{
			Label: bucketStart.Format("2006-01-02"),
			Start: bucketStart,
			End:   bucketStart.AddDate(0, 0, 1),
		})
	}

	return getDashboardTrend(e, domains, start, end, buckets)
}

func normalizeDashboardTrendDurationDays(durationDays int) int {
	switch durationDays {
	case 30, 60, 90, 120:
		return durationDays
	default:
		return 30
	}
}

func getDashboardTrend(e *config.Env, domains []string, start, end time.Time, buckets []trendBucket) (*DashboardTrend, error) {
	tb := (&model.AlertEventESDB{}).CollectName()
	startMs := start.UnixMilli()
	endMs := end.UnixMilli()

	queryParts := bson.A{
		bson.M{"$or": bson.A{
			bson.M{"end_ts": bson.M{"$gte": startMs, "$lt": endMs}},
			bson.M{"start_ts": bson.M{"$gte": startMs, "$lt": endMs}},
			bson.M{"create_tm": bson.M{"$gte": start, "$lt": end}},
		}},
	}
	if len(domains) > 0 {
		if domainFilter, ok := domainHostnameFilter(domains); ok {
			queryParts = append(queryParts, domainFilter)
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

	trend := newDashboardTrend(buckets)

	riskByDomain := make(map[string]*domainRisk)
	for _, domain := range domains {
		if domain != "" {
			riskByDomain[domain] = &domainRisk{Domain: domain}
		}
	}

	for _, alert := range alerts {
		alertTime := alertTrendTime(alert)
		bucketIdx := trendBucketIndex(alertTime, buckets)
		if bucketIdx < 0 {
			continue
		}

		trend.Total[bucketIdx]++
		switch alert.Level {
		case 5, 4:
			trend.High[bucketIdx]++
			if domain := matchDomain(alert.DcHostname, domains); domain != "" {
				risk := ensureDomainRisk(riskByDomain, domain)
				risk.HighAlerts++
			}
		case 3:
			trend.Medium[bucketIdx]++
		case 2:
			trend.Low[bucketIdx]++
		}

		switch alert.EventStatus {
		case 0:
			trend.AlertPending[bucketIdx]++
		case 1:
			trend.AlertHandled[bucketIdx]++
		case 2:
			trend.AlertWhitelisted[bucketIdx]++
		case 3:
			trend.AlertBlocked[bucketIdx]++
		}
	}

	if err := fillDomainRiskScanCounts(e, domains, riskByDomain, start, end); err != nil {
		logger.Errorf("fill domain risk scan counts err:%v", err)
		return nil, err
	}
	fillDomainRiskSeries(trend, riskByDomain)

	if err := fillScanTaskTrend(e, domains, start, end, buckets, trend); err != nil {
		logger.Errorf("fill scan task trend err:%v", err)
		return nil, err
	}

	return trend, nil
}

func newDashboardTrend(buckets []trendBucket) *DashboardTrend {
	length := len(buckets)
	trend := &DashboardTrend{
		Labels:               make([]string, length),
		Total:                make([]int32, length),
		High:                 make([]int32, length),
		Medium:               make([]int32, length),
		Low:                  make([]int32, length),
		AlertPending:         make([]int32, length),
		AlertHandled:         make([]int32, length),
		AlertWhitelisted:     make([]int32, length),
		AlertBlocked:         make([]int32, length),
		ScanLeakFinished:     make([]int32, length),
		ScanLeakFailed:       make([]int32, length),
		ScanLeakHits:         make([]int32, length),
		ScanBaselineFinished: make([]int32, length),
		ScanBaselineFailed:   make([]int32, length),
		ScanBaselineHits:     make([]int32, length),
		ScanWeakpwdFinished:  make([]int32, length),
		ScanWeakpwdFailed:    make([]int32, length),
		ScanWeakpwdHits:      make([]int32, length),
	}
	for index, bucket := range buckets {
		trend.Labels[index] = bucket.Label
	}
	return trend
}

func alertTrendTime(alert model.AlertEventESDB) time.Time {
	switch {
	case alert.EndTs > 0:
		return time.UnixMilli(alert.EndTs)
	case alert.StartTs > 0:
		return time.UnixMilli(alert.StartTs)
	default:
		return alert.CreateTm
	}
}

func trendBucketIndex(value time.Time, buckets []trendBucket) int {
	for index, bucket := range buckets {
		if !value.Before(bucket.Start) && value.Before(bucket.End) {
			return index
		}
	}
	return -1
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

func domainHostnameFilter(domains []string) (bson.M, bool) {
	domainFilters := make(bson.A, 0, len(domains))
	for _, domain := range domains {
		normalizedDomain := strings.TrimSpace(domain)
		if normalizedDomain == "" {
			continue
		}
		domainFilters = append(domainFilters, bson.M{
			"dc_hostname": bson.M{
				"$regex": bson.Regex{Pattern: ".*" + regexp.QuoteMeta(normalizedDomain) + "$", Options: "i"},
			},
		})
	}
	if len(domainFilters) == 0 {
		return nil, false
	}
	return bson.M{"$or": domainFilters}, true
}

func alertLevelKey(level int32) (string, bool) {
	switch level {
	case 5, 4:
		return "high", true
	case 3:
		return "medium", true
	case 2:
		return "low", true
	default:
		return "", false
	}
}

func fillDomainRiskSeries(trend *DashboardTrend, riskByDomain map[string]*domainRisk) {
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

func fillDomainRiskScanCounts(e *config.Env, domains []string, riskByDomain map[string]*domainRisk, start, end time.Time) error {
	for _, domain := range domains {
		if domain == "" {
			continue
		}
		risk := ensureDomainRisk(riskByDomain, domain)
		leaks, err := countHighRiskScanHitsInPeriod(e, domain, "leak", start, end)
		if err != nil {
			return err
		}
		baselines, err := countHighRiskScanHitsInPeriod(e, domain, "baseline", start, end)
		if err != nil {
			return err
		}
		risk.HighLeaks = leaks
		risk.HighBaselines = baselines
	}
	return nil
}

func countHighRiskScanHitsInPeriod(e *config.Env, domain, scanType string, start, end time.Time) (int32, error) {
	taskQuery := bson.D{
		{Key: "domain", Value: domain},
		{Key: "type", Value: scanType},
		{Key: "status", Value: "FINISH"},
		{Key: "create_tm", Value: bson.M{"$gte": start, "$lt": end}},
	}

	var tasks []model.ScanTasks
	if err := e.MongoCli.FindAll(e.MongoContext(), (&model.ScanTasks{}).CollectName(), taskQuery, &tasks); err != nil {
		return 0, err
	}
	if len(tasks) == 0 {
		return 0, nil
	}

	taskIDs := make([]string, 0, len(tasks))
	for _, task := range tasks {
		taskIDs = append(taskIDs, task.ID.Hex())
	}
	return countHighRiskScanHitsForTasks(e, domain, taskIDs)
}

func countHighRiskScanHitsForTasks(e *config.Env, domain string, taskIDs []string) (int32, error) {
	if len(taskIDs) == 0 {
		return 0, nil
	}
	subtaskQuery := bson.D{
		{Key: "status", Value: "FINISH"},
		{Key: "group_id", Value: bson.D{{Key: "$in", Value: taskIDs}}},
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

func fillScanTaskTrend(e *config.Env, domains []string, start, end time.Time, buckets []trendBucket, trend *DashboardTrend) error {
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

	taskIDsByTypeBucket := map[string]map[int][]string{
		"leak":     make(map[int][]string),
		"baseline": make(map[int][]string),
		"weakpwd":  make(map[int][]string),
	}
	for _, task := range tasks {
		bucketIdx := trendBucketIndex(task.CreateTm, buckets)
		if bucketIdx < 0 {
			continue
		}
		switch task.Type {
		case "leak":
			fillScanTaskStatus(task.Status, bucketIdx, trend.ScanLeakFinished, trend.ScanLeakFailed)
			taskIDsByTypeBucket["leak"][bucketIdx] = append(taskIDsByTypeBucket["leak"][bucketIdx], task.ID.Hex())
		case "baseline":
			fillScanTaskStatus(task.Status, bucketIdx, trend.ScanBaselineFinished, trend.ScanBaselineFailed)
			taskIDsByTypeBucket["baseline"][bucketIdx] = append(taskIDsByTypeBucket["baseline"][bucketIdx], task.ID.Hex())
		case "weakpwd":
			fillScanTaskStatus(task.Status, bucketIdx, trend.ScanWeakpwdFinished, trend.ScanWeakpwdFailed)
			taskIDsByTypeBucket["weakpwd"][bucketIdx] = append(taskIDsByTypeBucket["weakpwd"][bucketIdx], task.ID.Hex())
		}
	}

	for scanType, taskIDsByBucket := range taskIDsByTypeBucket {
		for bucketIdx, taskIDs := range taskIDsByBucket {
			hits, err := countScanHitsForTasks(e, taskIDs, scanType)
			if err != nil {
				return err
			}
			switch scanType {
			case "leak":
				trend.ScanLeakHits[bucketIdx] += hits
			case "baseline":
				trend.ScanBaselineHits[bucketIdx] += hits
			case "weakpwd":
				trend.ScanWeakpwdHits[bucketIdx] += hits
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
