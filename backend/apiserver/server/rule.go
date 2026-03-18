package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/model"
	"fmt"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Alert Rule (Flow Rules) Operations

func ListAlertRule(e *config.Env, levels []int32, status []string, enable *bool, keyword string, tags []string, sortTm int32, limit, offset int32) ([]*model.AlertRule, int64, error) {
	tb := (&model.AlertRule{}).CollectName()

	// Build query
	query := bson.D{}

	if len(levels) > 0 {
		query = append(query, bson.E{Key: "level", Value: bson.D{{Key: "$in", Value: levels}}})
	}

	if len(status) > 0 {
		query = append(query, bson.E{Key: "status", Value: bson.D{{Key: "$in", Value: status}}})
	}

	if enable != nil {
		query = append(query, bson.E{Key: "enable", Value: *enable})
	}

	if keyword != "" {
		// Search in title and description
		query = append(query, bson.E{Key: "$or", Value: []bson.M{
			{"title": bson.M{"$regex": keyword, "$options": "i"}},
			{"description": bson.M{"$regex": keyword, "$options": "i"}},
		}})
	}

	if len(tags) > 0 {
		query = append(query, bson.E{Key: "tags", Value: bson.D{{Key: "$in", Value: tags}}})
	}

	// Get total count
	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}

	// Sort
	sort := bson.M{"update_tm": -1}
	if sortTm != 0 {
		sort["update_tm"] = sortTm
	}

	// Find with pagination
	var rules []*model.AlertRule
	err = e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &rules, int64(limit), int64(offset))
	if err != nil {
		return nil, 0, err
	}

	return rules, total, nil
}

func AddAlertRule(e *config.Env, rule *model.AlertRule) error {
	tb := (&model.AlertRule{}).CollectName()

	// Set timestamps
	rule.CreateTm = time.Now()
	rule.UpdateTm = time.Now()

	// Generate ID if empty
	if rule.ID == "" {
		rule.ID = bson.NewObjectID().Hex()
	}

	return e.MongoCli.Insert(e.MongoContext(), tb, rule)
}

func UpdateAlertRule(e *config.Env, id string, updates bson.M) error {
	tb := (&model.AlertRule{}).CollectName()

	// Add update timestamp
	updates["update_tm"] = time.Now()

	filter := bson.M{"_id": id}

	return e.MongoCli.Update(e.MongoContext(), tb, filter, updates, false)
}

func DeleteAlertRule(e *config.Env, id string) error {
	tb := (&model.AlertRule{}).CollectName()
	filter := bson.M{"_id": id}
	return e.MongoCli.Remove(e.MongoContext(), tb, filter, false)
}

func GetAlertRuleByID(e *config.Env, id string) (*model.AlertRule, error) {
	tb := (&model.AlertRule{}).CollectName()
	filter := bson.M{"_id": id}

	var rule model.AlertRule
	err, exist := e.MongoCli.FindOne(e.MongoContext(), tb, filter, &rule)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, fmt.Errorf("rule not found")
	}

	return &rule, nil
}

// Activity Rule (Sigma Rules) Operations

func ListActivityRule(e *config.Env, ids []string, levels []int32, status []string, keyword string, tags []string, logsource string, ruleType string, sortTm int32, limit, offset int32) ([]*model.AlertActivityRule, int64, error) {
	tb := (&model.AlertActivityRule{}).CollectName()

	// Build query
	query := bson.D{}

	if len(ids) > 0 {
		query = append(query, bson.E{Key: "_id", Value: bson.D{{Key: "$in", Value: ids}}})
	}

	if len(levels) > 0 {
		query = append(query, bson.E{Key: "level", Value: bson.D{{Key: "$in", Value: levels}}})
	}

	if len(status) > 0 {
		query = append(query, bson.E{Key: "status", Value: bson.D{{Key: "$in", Value: status}}})
	}

	if keyword != "" {
		// Search in title and description
		query = append(query, bson.E{Key: "$or", Value: []bson.M{
			{"title": bson.M{"$regex": keyword, "$options": "i"}},
			{"description": bson.M{"$regex": keyword, "$options": "i"}},
		}})
	}

	if len(tags) > 0 {
		query = append(query, bson.E{Key: "tags", Value: bson.D{{Key: "$in", Value: tags}}})
	}

	if logsource != "" {
		query = append(query, bson.E{Key: "logsource", Value: logsource})
	}

	if ruleType != "" {
		// Rule type is determined by ID prefix: winlog-*, pktlog-*, flow-*
		query = append(query, bson.E{Key: "_id", Value: bson.M{"$regex": fmt.Sprintf("^%s-", ruleType)}})
	}

	// Get total count
	total, err := e.MongoCli.FindCount(e.MongoContext(), tb, query)
	if err != nil {
		return nil, 0, err
	}

	// Sort
	sort := bson.M{"update_tm": -1}
	if sortTm != 0 {
		sort["update_tm"] = sortTm
	}

	// Find with pagination
	var rules []*model.AlertActivityRule
	err = e.MongoCli.FindSortByLimitAndSkip(e.MongoContext(), tb, query, sort, &rules, int64(limit), int64(offset))
	if err != nil {
		return nil, 0, err
	}

	return rules, total, nil
}

func GetActivityRuleByID(e *config.Env, id string) (*model.AlertActivityRule, error) {
	tb := (&model.AlertActivityRule{}).CollectName()
	filter := bson.M{"_id": id}

	var rule model.AlertActivityRule
	err, exist := e.MongoCli.FindOne(e.MongoContext(), tb, filter, &rule)
	if err != nil {
		return nil, err
	}
	if !exist {
		return nil, fmt.Errorf("rule not found")
	}

	return &rule, nil
}

func AddActivityRule(e *config.Env, rule *model.AlertActivityRule) error {
	tb := (&model.AlertActivityRule{}).CollectName()

	// Set timestamps
	rule.CreateTm = time.Now()
	rule.UpdateTm = time.Now()

	// Validate ID format (should be like winlog-0000-0001, pktlog-0001, flow-0001)
	if !strings.Contains(rule.ID, "-") {
		return fmt.Errorf("invalid rule ID format, should be like: winlog-0000-0001")
	}

	return e.MongoCli.Insert(e.MongoContext(), tb, rule)
}

func UpdateActivityRule(e *config.Env, id string, updates bson.M) error {
	tb := (&model.AlertActivityRule{}).CollectName()

	// Add update timestamp
	updates["update_tm"] = time.Now()

	filter := bson.M{"_id": id}

	return e.MongoCli.Update(e.MongoContext(), tb, filter, updates, false)
}

func DeleteActivityRule(e *config.Env, id string) error {
	tb := (&model.AlertActivityRule{}).CollectName()
	filter := bson.M{"_id": id}
	return e.MongoCli.Remove(e.MongoContext(), tb, filter, false)
}

// CountAlertRulesReferencingActivityRule counts how many alert rules reference the given activity rule ID
func CountAlertRulesReferencingActivityRule(e *config.Env, activityRuleID string) (int64, error) {
	tb := (&model.AlertRule{}).CollectName()
	// Query alert rules where detection.sigma_rules contains the activity rule ID
	filter := bson.M{
		"detection.sigma_rules": activityRuleID,
	}
	count, err := e.MongoCli.FindCount(e.MongoContext(), tb, filter)
	if err != nil {
		return 0, err
	}
	return count, nil
}

// Helper: Convert level string to int32
func LevelStringToInt(level string) int32 {
	levelMap := map[string]int32{
		"info":     1,
		"low":      2,
		"medium":   3,
		"high":     4,
		"critical": 5,
	}
	if val, ok := levelMap[level]; ok {
		return val
	}
	return 3 // default to medium
}

// Helper: Convert level int32 to string
func LevelIntToString(level int32) string {
	levelMap := map[int32]string{
		1: "info",
		2: "low",
		3: "medium",
		4: "high",
		5: "critical",
	}
	if val, ok := levelMap[level]; ok {
		return val
	}
	return "medium"
}

// GetAllRuleTags returns all unique tags from AlertRule and AlertActivityRule collections
func GetAllRuleTags(e *config.Env) ([]string, error) {
	tagsMap := make(map[string]bool)

	// Get tags from AlertRule collection
	alertRuleTb := (&model.AlertRule{}).CollectName()
	var alertRules []model.AlertRule
	err := e.MongoCli.FindAll(e.MongoContext(), alertRuleTb, bson.D{}, &alertRules)
	if err != nil {
		logger.Errorf("find alert rules err:%v", err)
		return nil, err
	}

	for _, rule := range alertRules {
		for _, tag := range rule.Tags {
			if tag != "" {
				tagsMap[tag] = true
			}
		}
	}

	// Get tags from AlertActivityRule collection
	activityRuleTb := (&model.AlertActivityRule{}).CollectName()
	var activityRules []model.AlertActivityRule
	err = e.MongoCli.FindAll(e.MongoContext(), activityRuleTb, bson.D{}, &activityRules)
	if err != nil {
		logger.Errorf("find activity rules err:%v", err)
		return nil, err
	}

	for _, rule := range activityRules {
		for _, tag := range rule.Tags {
			if tag != "" {
				tagsMap[tag] = true
			}
		}
	}

	// Convert map to slice
	tags := make([]string, 0, len(tagsMap))
	for tag := range tagsMap {
		tags = append(tags, tag)
	}

	return tags, nil
}

// GetAllActivityRuleFields returns all unique fields from AlertActivityRule collection
func GetAllActivityRuleFields(e *config.Env) ([]string, error) {
	fieldsMap := make(map[string]bool)

	// Get fields from AlertActivityRule collection
	activityRuleTb := (&model.AlertActivityRule{}).CollectName()
	var activityRules []model.AlertActivityRule
	err := e.MongoCli.FindAll(e.MongoContext(), activityRuleTb, bson.D{}, &activityRules)
	if err != nil {
		logger.Errorf("find activity rules err:%v", err)
		return nil, err
	}

	for _, rule := range activityRules {
		for _, field := range rule.Fields {
			if field != "" {
				fieldsMap[field] = true
			}
		}
	}

	// Convert map to slice
	fields := make([]string, 0, len(fieldsMap))
	for field := range fieldsMap {
		fields = append(fields, field)
	}

	return fields, nil
}

// GetAllActivityRuleUniqueFields returns all unique uniqueFields from AlertActivityRule collection
func GetAllActivityRuleUniqueFields(e *config.Env) ([]string, error) {
	uniqueFieldsMap := make(map[string]bool)

	// Get uniqueFields from AlertActivityRule collection
	activityRuleTb := (&model.AlertActivityRule{}).CollectName()
	var activityRules []model.AlertActivityRule
	err := e.MongoCli.FindAll(e.MongoContext(), activityRuleTb, bson.D{}, &activityRules)
	if err != nil {
		logger.Errorf("find activity rules err:%v", err)
		return nil, err
	}

	for _, rule := range activityRules {
		for _, field := range rule.UniqueFields {
			if field != "" {
				uniqueFieldsMap[field] = true
			}
		}
	}

	// Convert map to slice
	uniqueFields := make([]string, 0, len(uniqueFieldsMap))
	for field := range uniqueFieldsMap {
		uniqueFields = append(uniqueFields, field)
	}

	return uniqueFields, nil
}

func GetThreatRuleByID(e *config.Env, flowId string) (*model.AlertRule, error) {
	ad := model.AlertRule{}

	err, _ := e.MongoCli.FindOne(e.MongoContext(), ad.CollectName(), bson.M{"_id": flowId}, &ad)
	if err != nil {
		logger.Errorf("get threat desc err:%v", err)
		return nil, err
	}

	return &ad, nil
}

func GetAllThreatRules(e *config.Env) ([]model.AlertRule, error) {
	var adList []model.AlertRule
	tb := (&model.AlertRule{}).CollectName()

	query := bson.M{}
	err := e.MongoCli.FindAll(e.MongoContext(), tb, query, &adList)
	if err != nil {
		return nil, err
	}
	return adList, nil
}

func FindThreatDescSelect(e *config.Env, levels []int32, enable []bool) ([]model.AlertRule, error) {
	var adList []model.AlertRule
	tb := (&model.AlertRule{}).CollectName()

	query := bson.M{}
	if len(levels) > 0 {
		query = bson.M{"level": bson.M{"$in": levels}}
	}
	if len(enable) > 0 {
		query = bson.M{"enable": bson.M{"$in": enable}}
	}

	err := e.MongoCli.FindAll(e.MongoContext(), tb, query, &adList)
	if err != nil {
		return nil, err
	}
	return adList, nil
}

// GetThreatAttackFlowByID 需要优化该处，修改为通用方法
func GetThreatAttackFlowByID(e *config.Env, flowId string, fieldData map[string]string) (*model.AttackFlow, error) {
	ad := model.AlertRule{}
	err, _ := e.MongoCli.FindOne(e.MongoContext(), ad.CollectName(), bson.M{"_id": flowId}, &ad)
	if err != nil {
		logger.Errorf("get threat attack_flow err:%v", err)
		return nil, err
	}

	// 获取攻击流图: 根据tb_alert_desc表中AttackFlow的定义，从fieldData中获取对应的字段值
	var attackInfo = model.AttackFlow{
		Fields:  []model.FieldObj{},
		Relates: ad.AttackFlow.Relates,
		Desc:    ad.AttackFlow.Desc,
	}

	for _, item := range ad.AttackFlow.Fields {
		// item is now a FieldObj struct with Obj, Key, Value fields
		if item.Obj == "" || item.Key == "" {
			continue
		}

		// Create a new FieldObj to store the extracted data
		fieldObj := model.FieldObj{
			Obj:   item.Obj,
			Key:   item.Key,
			Value: item.Value,
		}

		// Try to extract value from fieldData using the Key
		for fieldKey, fieldVal := range fieldData {
			if strings.HasSuffix(fieldKey, item.Key) {
				// fieldKey格式: $s1.field_TargetUserName, 这里按field_截取
				parts := strings.Split(fieldKey, ".field_")
				if len(parts) != 2 {
					continue
				}

				// Update the key and value with extracted data
				fieldObj.Key = parts[1]
				fieldObj.Value = fieldVal
				break
			}
		}

		attackInfo.Fields = append(attackInfo.Fields, fieldObj)
	}

	return &attackInfo, nil
}
