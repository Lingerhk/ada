package service

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/server"
	"ada/backend/common"
	"ada/backend/model"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"gopkg.in/yaml.v3"
)

// Helper: Parse YAML string to ActivityDetection
func parseActivityDetectionYAML(detectionStr string) (model.ActivityDetection, error) {
	var detection model.ActivityDetection
	err := yaml.Unmarshal([]byte(detectionStr), &detection)
	if err != nil {
		logger.Errorf("Failed to parse detection YAML: %v", err)
		return model.ActivityDetection{}, err
	}
	return detection, nil
}

// Helper: Convert AlertDetection/ActivityDetection to YAML string
func detectionToYAML(detection any) (string, error) {
	buf := new(bytes.Buffer)
	encoder := yaml.NewEncoder(buf)
	encoder.SetIndent(4) // 设置为 4 个空格缩进
	defer encoder.Close()
	if err := encoder.Encode(detection); err != nil {
		logger.Errorf("Failed to marshal detection to YAML: %v", err)
		return "", err
	}

	return buf.String(), nil
}

func normalizeRuleOrigin(origin, fallback string) string {
	origin = strings.ToLower(strings.TrimSpace(origin))
	switch origin {
	case "internal", "public", "custom":
		return origin
	}
	if fallback != "" {
		return fallback
	}
	return "custom"
}

// Alert Rule methods

func (s *ADAServiceV2) ListAlertRule(ctx context.Context, in *v2.ListAlertRuleReq) (*v2.ListAlertRuleReply, error) {
	s = s.withContext(ctx)
	limit := in.PageSize
	if limit == 0 {
		limit = 10
	}
	offset := (in.PageIdx - 1) * limit

	var enablePtr *bool
	if in.Enable {
		enablePtr = &in.Enable
	}

	rules, total, err := server.ListAlertRule(
		s.env,
		in.Level,
		in.Status,
		enablePtr,
		in.Keyword,
		in.Tags,
		in.SortTm,
		limit,
		offset,
	)
	if err != nil {
		logger.Errorf("ListAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.AlertRule.QueryFailed"))
	}

	// Convert to reply
	var ruleInfos []*v2.AlertRuleInfo
	for _, rule := range rules {
		// Ensure tags is never nil
		tags := rule.Tags
		if tags == nil {
			tags = []string{}
		}

		detectionStr := ""
		// Check if detection has any content
		if rule.Detection.EventType != "" || len(rule.Detection.SigmaRules) > 0 {
			var err error
			detectionStr, err = detectionToYAML(rule.Detection)
			if err != nil {
				logger.Errorf("Failed to marshal detection to YAML for rule %s: %v", rule.ID, err)
				// Set empty string and continue with other fields
				detectionStr = ""
			}
		}

		// Convert AttackFlow from model to proto
		var fieldsProto []*v2.AttackFlowReply_Field
		if rule.AttackFlow.Fields != nil {
			for _, field := range rule.AttackFlow.Fields {
				fieldsProto = append(fieldsProto, &v2.AttackFlowReply_Field{
					Obj: field.Obj,
					Key: field.Key,
				})
			}
		}
		relates := rule.AttackFlow.Relates
		if relates == nil {
			relates = []string{}
		}
		attackFlowProto := &v2.AttackFlowReply{
			Desc:    rule.AttackFlow.Desc,
			Fields:  fieldsProto,
			Relates: relates,
		}

		// Ensure uniqueFilter is never nil
		uniqueFilter := rule.UniqueFilter
		if uniqueFilter == nil {
			uniqueFilter = []string{}
		}

		ruleInfo := &v2.AlertRuleInfo{
			ID:           rule.ID,
			Title:        rule.Title,
			Description:  rule.Description,
			Enable:       rule.Enable,
			Level:        rule.Level,
			Status:       rule.Status,
			Tags:         tags,
			Logsource:    rule.Logsource,
			Detection:    detectionStr,
			Type:         rule.Type,
			RuleOrigin:   normalizeRuleOrigin(rule.RuleOrigin, "internal"),
			Author:       rule.Author,
			References:   rule.References,
			Suggestion:   rule.Suggestion,
			AutoBlock:    rule.AutoBlock,
			AttackFlow:   attackFlowProto,
			UniqueFilter: uniqueFilter,
			CreateTm:     rule.CreateTm.Format("2006-01-02 15:04:05"),
			UpdateTm:     rule.UpdateTm.Format("2006-01-02 15:04:05"),
		}
		ruleInfos = append(ruleInfos, ruleInfo)
	}

	return &v2.ListAlertRuleReply{
		Page: &v2.ModelPage{
			Total:   int32(total),
			PageIdx: in.PageIdx,
		},
		Rules: ruleInfos,
	}, nil
}

func (s *ADAServiceV2) AddAlertRule(ctx context.Context, in *v2.AddAlertRuleReq) (*v2.AddAlertRuleReply, error) {
	s = s.withContext(ctx)
	// If ID is provided, check if rule with this ID already exists
	if in.ID != "" {
		existingRule, err := server.GetAlertRuleByID(s.env, in.ID)
		if err == nil && existingRule != nil {
			errMsg := fmt.Sprintf(s.I18n("Threat.AlertRule.IDAlreadyExists"), in.ID)
			return nil, status.Error(codes.AlreadyExists, errMsg)
		}
	}

	// Convert detection from proto to model
	detection := model.AlertDetection{
		EventType:  in.Detection.GetEventType(),
		WinSize:    in.Detection.GetWinSize(),
		Sorted:     in.Detection.GetSorted(),
		SigmaRules: in.Detection.GetSigmaRules(),
		MatchBy:    in.Detection.GetMatchBy(),
	}

	// Convert AttackFlow from proto to model
	var fieldsModel []model.FieldObj
	if in.AttackFlow != nil {
		for _, field := range in.AttackFlow.Fields {
			fieldsModel = append(fieldsModel, model.FieldObj{
				Obj: field.Obj,
				Key: field.Key,
			})
		}
	}
	attackFlow := model.AttackFlow{
		Desc:    in.AttackFlow.GetDesc(),
		Fields:  fieldsModel,
		Relates: in.AttackFlow.GetRelates(),
	}

	rule := &model.AlertRule{
		ID:           in.ID,
		Title:        in.Title,
		Description:  in.Description,
		Enable:       in.Enable,
		Level:        in.Level,
		Status:       in.Status,
		Tags:         in.Tags,
		Logsource:    in.Logsource,
		Detection:    detection,
		Type:         in.Type,
		RuleOrigin:   normalizeRuleOrigin(in.RuleOrigin, "custom"),
		References:   in.References,
		Suggestion:   in.Suggestion,
		Author:       in.Author,
		AutoBlock:    in.AutoBlock,
		AttackFlow:   attackFlow,
		UniqueFilter: in.UniqueFilter,
	}

	err := server.AddAlertRule(s.env, rule)
	if err != nil {
		logger.Errorf("AddAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.AlertRule.AddFailed"))
	}

	// Write rule to disk file
	if err := server.WriteAlertRuleToFile(rule); err != nil {
		logger.Errorf("Failed to write alert rule to file: %v", err)
		// Don't fail the request, just log the error
	}

	// Generate version.txt file after rule is written
	if err := server.GenerateVersionFile(); err != nil {
		logger.Errorf("Failed to generate version file: %v", err)
	}

	// Send reload signal to engine via Redis
	if err := server.SendReloadSignalToEngine(s.env); err != nil {
		logger.Errorf("Failed to send reload signal to engine: %v", err)
	}

	return &v2.AddAlertRuleReply{
		ID:     rule.ID,
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) UpdateAlertRule(ctx context.Context, in *v2.UpdateAlertRuleReq) (*v2.UpdateAlertRuleReply, error) {
	s = s.withContext(ctx)
	updates := bson.M{}

	if in.Title != "" {
		updates["title"] = in.Title
	}
	if in.Description != "" {
		updates["description"] = in.Description
	}
	// Always update boolean fields (enable and autoBlock) to allow setting them to false
	updates["enable"] = in.Enable
	updates["auto_block"] = in.AutoBlock

	if in.Level > 0 {
		updates["level"] = in.Level
	}
	if in.Status != "" {
		updates["status"] = in.Status
	}
	if len(in.Tags) > 0 {
		updates["tags"] = in.Tags
	}
	if in.Logsource != "" {
		updates["logsource"] = in.Logsource
	}
	if in.Detection != nil {
		detection := model.AlertDetection{
			EventType:  in.Detection.GetEventType(),
			WinSize:    in.Detection.GetWinSize(),
			Sorted:     in.Detection.GetSorted(),
			SigmaRules: in.Detection.GetSigmaRules(),
			MatchBy:    in.Detection.GetMatchBy(),
		}
		updates["detection"] = detection
	}
	if in.Type != "" {
		updates["type"] = in.Type
	}
	if in.RuleOrigin != "" {
		updates["rule_origin"] = normalizeRuleOrigin(in.RuleOrigin, "custom")
	}
	if len(in.References) > 0 {
		updates["references"] = in.References
	}
	if in.Suggestion != "" {
		updates["suggestion"] = in.Suggestion
	}
	if in.Author != "" {
		updates["author"] = in.Author
	}
	if in.AttackFlow != nil {
		// Convert AttackFlow from proto to model
		var fieldsModel []model.FieldObj
		for _, field := range in.AttackFlow.Fields {
			fieldsModel = append(fieldsModel, model.FieldObj{
				Obj: field.Obj,
				Key: field.Key,
			})
		}
		attackFlowModel := model.AttackFlow{
			Desc:    in.AttackFlow.Desc,
			Fields:  fieldsModel,
			Relates: in.AttackFlow.Relates,
		}
		updates["attack_flow"] = attackFlowModel
	}
	if len(in.UniqueFilter) > 0 {
		updates["unique_filter"] = in.UniqueFilter
	}

	err := server.UpdateAlertRule(s.env, in.ID, updates)
	if err != nil {
		logger.Errorf("UpdateAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.AlertRule.UpdateFailed"))
	}

	// Fetch updated rule from database and write to file
	updatedRule, err := server.GetAlertRuleByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("Failed to fetch updated rule: %v", err)
	} else {
		if err := server.WriteAlertRuleToFile(updatedRule); err != nil {
			logger.Errorf("Failed to write updated alert rule to file: %v", err)
		}

		// Generate version.txt file after rule is updated
		if err := server.GenerateVersionFile(); err != nil {
			logger.Errorf("Failed to generate version file: %v", err)
		}

		// Send SIGHUP to engine to reload rules
		if err := server.SendReloadSignalToEngine(s.env); err != nil {
			logger.Errorf("Failed to send SIGHUP to engine: %v", err)
		}
	}

	return &v2.UpdateAlertRuleReply{
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) DeleteAlertRule(ctx context.Context, in *v2.DeleteAlertRuleReq) (*v2.DeleteAlertRuleReply, error) {
	s = s.withContext(ctx)
	err := server.DeleteAlertRule(s.env, in.ID)
	if err != nil {
		logger.Errorf("DeleteAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.AlertRule.DeleteFailed"))
	}

	// Delete rule file from disk
	if err := server.DeleteAlertRuleFile(in.ID); err != nil {
		logger.Errorf("Failed to delete alert rule file: %v", err)
	}

	// Send SIGHUP to engine to reload rules
	if err := server.SendReloadSignalToEngine(s.env); err != nil {
		logger.Errorf("Failed to send SIGHUP to engine: %v", err)
	}

	return &v2.DeleteAlertRuleReply{
		Result: "SUCCESS",
	}, nil
}

// GetAlertTypes
func (s *ADAServiceV2) GetAlertTypes(ctx context.Context, in *v2.GetAlertTypesReq) (*v2.GetAlertTypesReply, error) {
	s = s.withContext(ctx)
	return &v2.GetAlertTypesReply{
		AlertTypes: common.RuleTypeMap,
	}, nil
}

// GetAlertRuleNames returns alert rule names mapping (rule_id -> rule_name)
func (s *ADAServiceV2) GetAlertRuleNames(ctx context.Context, in *v2.GetAlertRuleNamesReq) (*v2.GetAlertRuleNamesReply, error) {
	s = s.withContext(ctx)
	var nameMap = make(map[string]string)

	if in.RuleId != "" {
		// Get specific rule by ID
		rule, err := server.GetAlertRuleByID(s.env, in.RuleId)
		if err != nil {
			logger.Errorf("get alert rule by id(%s) err:%v", in.RuleId, err)
			return nil, status.Error(codes.Internal, s.I18n("QueryFailed"))
		}
		nameMap[rule.ID] = rule.Title
		return &v2.GetAlertRuleNamesReply{Names: nameMap}, nil
	}

	// Get all alert rules
	rules, _, err := server.ListAlertRule(s.env, []int32{}, []string{}, nil, "", []string{}, -1, -1, -1)
	if err != nil {
		logger.Errorf("list all alert rules err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("QueryFailed"))
	}

	for _, rule := range rules {
		nameMap[rule.ID] = rule.Title
	}

	return &v2.GetAlertRuleNamesReply{Names: nameMap}, nil
}

// GetAlertRuleTags
func (s *ADAServiceV2) GetAlertRuleTags(ctx context.Context, in *v2.GetAlertRuleTagsReq) (*v2.GetAlertRuleTagsReply, error) {
	s = s.withContext(ctx)
	tags, err := server.GetAllRuleTags(s.env)
	if err != nil {
		logger.Errorf("get all rule tags err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}
	return &v2.GetAlertRuleTagsReply{
		Tags: tags,
	}, nil
}

// Activity Rule methods (Sigma rules)

// GetActivityRuleFields
func (s *ADAServiceV2) GetActivityRuleFields(ctx context.Context, in *v2.GetActivityRuleFieldsReq) (*v2.GetActivityRuleFieldsReply, error) {
	s = s.withContext(ctx)
	fields, err := server.GetAllActivityRuleFields(s.env)
	if err != nil {
		logger.Errorf("get all activity rule fields err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}
	return &v2.GetActivityRuleFieldsReply{
		Fields: fields,
	}, nil
}

// GetActivityRuleUniqueFields
func (s *ADAServiceV2) GetActivityRuleNames(ctx context.Context, in *v2.GetActivityRuleNamesReq) (*v2.GetActivityRuleNamesReply, error) {
	s = s.withContext(ctx)
	// Get all activity rules without filters
	rules, _, err := server.ListActivityRule(s.env, []string{}, []int32{}, []string{}, "", []string{}, "", "", -1, 10000, 0)
	if err != nil {
		logger.Errorf("get all activity rules err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	ruleItems := make([]*v2.RuleNameItem, 0, len(rules))
	for _, rule := range rules {
		ruleItems = append(ruleItems, &v2.RuleNameItem{
			RuleId: rule.ID,
			Title:  rule.Title,
		})
	}

	return &v2.GetActivityRuleNamesReply{
		Rules: ruleItems,
	}, nil
}

func (s *ADAServiceV2) GetActivityRuleUniqueFields(ctx context.Context, in *v2.GetActivityRuleUniqueFieldsReq) (*v2.GetActivityRuleUniqueFieldsReply, error) {
	s = s.withContext(ctx)
	uniqueFields, err := server.GetAllActivityRuleUniqueFields(s.env)
	if err != nil {
		logger.Errorf("get all activity rule unique fields err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}
	return &v2.GetActivityRuleUniqueFieldsReply{
		UniqueFields: uniqueFields,
	}, nil
}

func (s *ADAServiceV2) ListActivityRule(ctx context.Context, in *v2.ListActivityRuleReq) (*v2.ListActivityRuleReply, error) {
	s = s.withContext(ctx)
	limit := in.PageSize
	if limit == 0 {
		limit = 10
	}
	offset := (in.PageIdx - 1) * limit

	rules, total, err := server.ListActivityRule(
		s.env,
		in.IDs,
		in.Level,
		in.Status,
		in.Keyword,
		in.Tags,
		in.Logsource,
		in.RuleType,
		in.SortTm,
		limit,
		offset,
	)
	if err != nil {
		logger.Errorf("ListActivityRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.ActivityRule.QueryFailed"))
	}

	// Convert to reply
	var ruleInfos []*v2.ActivityRuleInfo
	for _, rule := range rules {
		// Ensure slices are never nil
		tags := rule.Tags
		if tags == nil {
			tags = []string{}
		}
		fields := rule.Fields
		if fields == nil {
			fields = []string{}
		}
		uniqueFields := rule.UniqueFields
		if uniqueFields == nil {
			uniqueFields = []string{}
		}

		// Serialize detection to YAML string
		detectionStr := ""
		if rule.Detection != nil {
			if data, err := detectionToYAML(rule.Detection); err == nil {
				detectionStr = string(data)
			}
		}

		ruleInfo := &v2.ActivityRuleInfo{
			ID:           rule.ID,
			Title:        rule.Title,
			Description:  rule.Description,
			Level:        rule.Level,
			Status:       rule.Status,
			Tags:         tags,
			Logsource:    rule.Logsource,
			RuleOrigin:   normalizeRuleOrigin(rule.RuleOrigin, "internal"),
			References:   rule.References,
			Detection:    detectionStr,
			RdxKey:       rule.RdxKey,
			Fields:       fields,
			UniqueFields: uniqueFields,
			Author:       rule.Author,
			CreateTm:     rule.CreateTm.Format("2006-01-02 15:04:05"),
			UpdateTm:     rule.UpdateTm.Format("2006-01-02 15:04:05"),
		}
		ruleInfos = append(ruleInfos, ruleInfo)
	}

	return &v2.ListActivityRuleReply{
		Page: &v2.ModelPage{
			Total:   int32(total),
			PageIdx: in.PageIdx,
		},
		Rules: ruleInfos,
	}, nil
}

func (s *ADAServiceV2) GetActivityRule(ctx context.Context, in *v2.GetActivityRuleReq) (*v2.GetActivityRuleReply, error) {
	s = s.withContext(ctx)
	rule, err := server.GetActivityRuleByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("GetActivityRule failed: %v", err)
		return nil, status.Error(codes.NotFound, s.I18n("Threat.ActivityRule.NotFound"))
	}

	detectionStr := ""
	if rule.Detection != nil {
		if data, err := detectionToYAML(rule.Detection); err == nil {
			detectionStr = string(data)
		}
	}

	return &v2.GetActivityRuleReply{
		ID:           rule.ID,
		Title:        rule.Title,
		Description:  rule.Description,
		Level:        rule.Level,
		Status:       rule.Status,
		Tags:         rule.Tags,
		Logsource:    rule.Logsource,
		RuleOrigin:   normalizeRuleOrigin(rule.RuleOrigin, "internal"),
		References:   rule.References,
		Detection:    detectionStr,
		RdxKey:       rule.RdxKey,
		Fields:       rule.Fields,
		UniqueFields: rule.UniqueFields,
		Author:       rule.Author,
		CreateTm:     rule.CreateTm.Format("2006-01-02 15:04:05"),
		UpdateTm:     rule.UpdateTm.Format("2006-01-02 15:04:05"),
	}, nil
}

func (s *ADAServiceV2) AddActivityRule(ctx context.Context, in *v2.AddActivityRuleReq) (*v2.AddActivityRuleReply, error) {
	s = s.withContext(ctx)
	// Parse detection YAML
	detection, err := parseActivityDetectionYAML(in.Detection)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, s.I18n("Threat.ActivityRule.InvalidDetectionFormat"))
	}

	rule := &model.AlertActivityRule{
		ID:           in.ID,
		Title:        in.Title,
		Description:  in.Description,
		Level:        in.Level,
		Status:       in.Status,
		Tags:         in.Tags,
		Logsource:    in.Logsource,
		RuleOrigin:   normalizeRuleOrigin(in.RuleOrigin, "custom"),
		References:   in.References,
		Detection:    detection,
		RdxKey:       in.RdxKey,
		Fields:       in.Fields,
		UniqueFields: in.UniqueFields,
		Author:       in.Author,
	}

	err = server.AddActivityRule(s.env, rule)
	if err != nil {
		logger.Errorf("AddActivityRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.ActivityRule.AddFailed"))
	}

	// Write rule to disk file
	if err := server.WriteActivityRuleToFile(rule); err != nil {
		logger.Errorf("Failed to write activity rule to file: %v", err)
	}

	// Generate version.txt file after rule is written
	if err := server.GenerateVersionFile(); err != nil {
		logger.Errorf("Failed to generate version file: %v", err)
	}

	// Send SIGHUP to engine to reload rules
	if err := server.SendReloadSignalToEngine(s.env); err != nil {
		logger.Errorf("Failed to send SIGHUP to engine: %v", err)
	}

	return &v2.AddActivityRuleReply{
		ID:     rule.ID,
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) UpdateActivityRule(ctx context.Context, in *v2.UpdateActivityRuleReq) (*v2.UpdateActivityRuleReply, error) {
	s = s.withContext(ctx)
	updates := bson.M{}

	if in.Title != "" {
		updates["title"] = in.Title
	}
	if in.Description != "" {
		updates["description"] = in.Description
	}
	if in.Level > 0 {
		updates["level"] = in.Level
	}
	if in.Status != "" {
		updates["status"] = in.Status
	}
	if len(in.Tags) > 0 {
		updates["tags"] = in.Tags
	}
	if in.Logsource != "" {
		updates["logsource"] = in.Logsource
	}
	if in.RuleOrigin != "" {
		updates["rule_origin"] = normalizeRuleOrigin(in.RuleOrigin, "custom")
	}
	if len(in.References) > 0 {
		updates["references"] = in.References
	}
	if in.Detection != "" {
		detection, err := parseActivityDetectionYAML(in.Detection)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, s.I18n("Threat.ActivityRule.InvalidDetectionFormat"))
		}
		updates["detection"] = detection
	}
	if in.RdxKey != "" {
		updates["rdx_key"] = in.RdxKey
	}
	if len(in.Fields) > 0 {
		updates["fields"] = in.Fields
	}
	if len(in.UniqueFields) > 0 {
		updates["unique_fields"] = in.UniqueFields
	}
	if in.Author != "" {
		updates["author"] = in.Author
	}

	err := server.UpdateActivityRule(s.env, in.ID, updates)
	if err != nil {
		logger.Errorf("UpdateActivityRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.ActivityRule.UpdateFailed"))
	}

	// Fetch updated rule from database and write to file
	updatedRule, err := server.GetActivityRuleByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("Failed to fetch updated activity rule: %v", err)
	} else {
		if err := server.WriteActivityRuleToFile(updatedRule); err != nil {
			logger.Errorf("Failed to write updated activity rule to file: %v", err)
		}

		// Generate version.txt file after rule is updated
		if err := server.GenerateVersionFile(); err != nil {
			logger.Errorf("Failed to generate version file: %v", err)
		}

		// Send SIGHUP to engine to reload rules
		if err := server.SendReloadSignalToEngine(s.env); err != nil {
			logger.Errorf("Failed to send SIGHUP to engine: %v", err)
		}
	}

	return &v2.UpdateActivityRuleReply{
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) DeleteActivityRule(ctx context.Context, in *v2.DeleteActivityRuleReq) (*v2.DeleteActivityRuleReply, error) {
	s = s.withContext(ctx)
	// Check if any alert rules reference this activity rule
	count, err := server.CountAlertRulesReferencingActivityRule(s.env, in.ID)
	if err != nil {
		logger.Errorf("Failed to check alert rules referencing activity rule: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("InternalError"))
	}

	if count > 0 {
		// Return error message with count
		errorMsg := fmt.Sprintf(s.I18n("Threat.ActivityRule.ReferencedByAlertRules"), count)
		return nil, status.Error(codes.FailedPrecondition, errorMsg)
	}

	err = server.DeleteActivityRule(s.env, in.ID)
	if err != nil {
		logger.Errorf("DeleteActivityRule failed: %v", err)
		return nil, status.Error(codes.Internal, s.I18n("Threat.ActivityRule.DeleteFailed"))
	}

	// Delete rule file from disk
	if err := server.DeleteActivityRuleFile(in.ID); err != nil {
		logger.Errorf("Failed to delete activity rule file: %v", err)
	}

	// Send SIGHUP to engine to reload rules
	if err := server.SendReloadSignalToEngine(s.env); err != nil {
		logger.Errorf("Failed to send SIGHUP to engine: %v", err)
	}

	return &v2.DeleteActivityRuleReply{
		Result: "SUCCESS",
	}, nil
}
