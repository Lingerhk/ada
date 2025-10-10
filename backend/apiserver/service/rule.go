package service

import (
	"context"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/server"
	"ada/backend/model"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Alert Rule methods

func (s *ADAServiceV2) ListAlertRule(ctx context.Context, in *v2.ListAlertRuleReq) (*v2.ListAlertRuleReply, error) {
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
		in.IDs,
		in.Level,
		in.Status,
		enablePtr,
		in.Keyword,
		in.Tags,
		in.Logsource,
		in.SortTm,
		limit,
		offset,
	)
	if err != nil {
		logger.Errorf("ListAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, "查询告警规则失败")
	}

	// Convert to reply
	var ruleInfos []*v2.AlertRuleInfo
	for _, rule := range rules {
		ruleInfo := &v2.AlertRuleInfo{
			ID:          rule.ID,
			Title:       rule.Title,
			Description: rule.Description,
			Enable:      rule.Enable,
			Level:       rule.Level,
			Status:      rule.Status,
			Tags:        rule.Tags,
			Logsource:   rule.Logsource,
			Type:        rule.Type,
			Author:      rule.Author,
			AutoBlock:   rule.AutoBlock,
			CreateTm:    rule.CreateTm.Format("2006-01-02 15:04:05"),
			UpdateTm:    rule.UpdateTm.Format("2006-01-02 15:04:05"),
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
	// Parse detection JSON
	detection, err := server.ParseDetectionJSON(in.Detection)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "检测配置JSON格式错误")
	}

	rule := &model.AlertRule{
		Title:       in.Title,
		Description: in.Description,
		Enable:      in.Enable,
		Level:       in.Level,
		Status:      in.Status,
		Tags:        in.Tags,
		Logsource:   in.Logsource,
		Detection: model.AlertDetection{
			EventType:  detection["event_type"].(string),
			MatchBy:    detection["match_by"].(string),
		},
		Type:       in.Type,
		Reference: in.Reference,
		Suggestion: in.Suggestion,
		Author:     in.Author,
		AutoBlock:  in.AutoBlock,
	}

	// Handle optional fields in detection
	if winSize, ok := detection["win_size"].(float64); ok {
		rule.Detection.WinSize = int64(winSize)
	}
	if sorted, ok := detection["sorted"].(bool); ok {
		rule.Detection.Sorted = sorted
	}
	if sigmaRules, ok := detection["sigma_rules"].([]interface{}); ok {
		for _, sr := range sigmaRules {
			if s, ok := sr.(string); ok {
				rule.Detection.SigmaRules = append(rule.Detection.SigmaRules, s)
			}
		}
	}

	err = server.AddAlertRule(s.env, rule)
	if err != nil {
		logger.Errorf("AddAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, "添加告警规则失败")
	}

	return &v2.AddAlertRuleReply{
		ID:     rule.ID,
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) UpdateAlertRule(ctx context.Context, in *v2.UpdateAlertRuleReq) (*v2.UpdateAlertRuleReply, error) {
	updates := bson.M{}

	if in.Title != "" {
		updates["title"] = in.Title
	}
	if in.Description != "" {
		updates["description"] = in.Description
	}
	if in.Enable {
		updates["enable"] = in.Enable
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
	if in.Detection != "" {
		detection, err := server.ParseDetectionJSON(in.Detection)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "检测配置JSON格式错误")
		}
		updates["detection"] = detection
	}
	if in.Type != "" {
		updates["type"] = in.Type
	}
	if in.Reference != "" {
		updates["reference"] = in.Reference
	}
	if in.Suggestion != "" {
		updates["suggestion"] = in.Suggestion
	}
	if in.Author != "" {
		updates["author"] = in.Author
	}
	if in.AutoBlock {
		updates["auto_block"] = in.AutoBlock
	}

	err := server.UpdateAlertRule(s.env, in.ID, updates)
	if err != nil {
		logger.Errorf("UpdateAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, "更新告警规则失败")
	}

	return &v2.UpdateAlertRuleReply{
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) DeleteAlertRule(ctx context.Context, in *v2.DeleteAlertRuleReq) (*v2.DeleteAlertRuleReply, error) {
	err := server.DeleteAlertRule(s.env, in.ID)
	if err != nil {
		logger.Errorf("DeleteAlertRule failed: %v", err)
		return nil, status.Error(codes.Internal, "删除告警规则失败")
	}

	return &v2.DeleteAlertRuleReply{
		Result: "SUCCESS",
	}, nil
}

// Activity Rule methods (Sigma rules)

func (s *ADAServiceV2) ListActivityRule(ctx context.Context, in *v2.ListActivityRuleReq) (*v2.ListActivityRuleReply, error) {
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
		return nil, status.Error(codes.Internal, "查询Sigma规则失败")
	}

	// Convert to reply
	var ruleInfos []*v2.ActivityRuleInfo
	for _, rule := range rules {
		ruleInfo := &v2.ActivityRuleInfo{
			ID:           rule.ID,
			Title:        rule.Title,
			Description:  rule.Description,
			Level:        rule.Level,
			Status:       rule.Status,
			Tags:         rule.Tags,
			Logsource:    rule.Logsource,
			Reference:    rule.Reference,
			RdxKey:       rule.RdxKey,
			Fields:       rule.Fields,
			UniqueFields: rule.UniqueFields,
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
	rule, err := server.GetActivityRuleByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("GetActivityRule failed: %v", err)
		return nil, status.Error(codes.NotFound, "Sigma规则不存在")
	}

	// Convert detection to JSON
	detectionJSON, err := server.DetectionToJSON(rule.Detection)
	if err != nil {
		logger.Errorf("Failed to convert detection to JSON: %v", err)
		return nil, status.Error(codes.Internal, "获取规则详情失败")
	}

	return &v2.GetActivityRuleReply{
		ID:           rule.ID,
		Title:        rule.Title,
		Description:  rule.Description,
		Level:        rule.Level,
		Status:       rule.Status,
		Tags:         rule.Tags,
		Logsource:    rule.Logsource,
		Reference:    rule.Reference,
		Detection:    detectionJSON,
		RdxKey:       rule.RdxKey,
		Fields:       rule.Fields,
		UniqueFields: rule.UniqueFields,
		Author:       rule.Author,
		CreateTm:     rule.CreateTm.Format("2006-01-02 15:04:05"),
		UpdateTm:     rule.UpdateTm.Format("2006-01-02 15:04:05"),
	}, nil
}

func (s *ADAServiceV2) AddActivityRule(ctx context.Context, in *v2.AddActivityRuleReq) (*v2.AddActivityRuleReply, error) {
	// Parse detection JSON
	detection, err := server.ParseDetectionJSON(in.Detection)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "检测配置JSON格式错误")
	}

	rule := &model.AlertActivityRule{
		ID:           in.ID,
		Title:        in.Title,
		Description:  in.Description,
		Level:        in.Level,
		Status:       in.Status,
		Tags:         in.Tags,
		Logsource:    in.Logsource,
		Reference:    in.Reference,
		Detection:    detection,
		RdxKey:       in.RdxKey,
		Fields:       in.Fields,
		UniqueFields: in.UniqueFields,
		Author:       in.Author,
	}

	err = server.AddActivityRule(s.env, rule)
	if err != nil {
		logger.Errorf("AddActivityRule failed: %v", err)
		return nil, status.Error(codes.Internal, "添加Sigma规则失败")
	}

	return &v2.AddActivityRuleReply{
		ID:     rule.ID,
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) UpdateActivityRule(ctx context.Context, in *v2.UpdateActivityRuleReq) (*v2.UpdateActivityRuleReply, error) {
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
	if in.Reference != "" {
		updates["reference"] = in.Reference
	}
	if in.Detection != "" {
		detection, err := server.ParseDetectionJSON(in.Detection)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "检测配置JSON格式错误")
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
		return nil, status.Error(codes.Internal, "更新Sigma规则失败")
	}

	return &v2.UpdateActivityRuleReply{
		Result: "SUCCESS",
	}, nil
}

func (s *ADAServiceV2) DeleteActivityRule(ctx context.Context, in *v2.DeleteActivityRuleReq) (*v2.DeleteActivityRuleReply, error) {
	err := server.DeleteActivityRule(s.env, in.ID)
	if err != nil {
		logger.Errorf("DeleteActivityRule failed: %v", err)
		return nil, status.Error(codes.Internal, "删除Sigma规则失败")
	}

	return &v2.DeleteActivityRuleReply{
		Result: "SUCCESS",
	}, nil
}
