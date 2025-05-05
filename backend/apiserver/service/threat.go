package service

import (
	sCommon "ada/agent/sensor/common"
	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/config"
	"ada/backend/apiserver/server"
	"ada/backend/cache"
	bCommon "ada/backend/common"
	"ada/infra/base"
	"ada/infra/crypto"
	"ada/infra/version"
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func snakeString(s string) string {
	m := map[string]string{
		"domain":      "domain",
		"threatID":    "rule_id",
		"threatLevel": "risk_level",
		"status":      "status",
		"time":        "end_tm",
		"source":      "source",
		"target":      "target",
	}
	return m[s]
}

func getAttackFlow(env *config.Env, flowId string, fieldData map[string]string) *v2.AttackFlowReply {
	attackFlow, err := server.GetThreatFlowByID(env, flowId, fieldData)
	if err != nil {
		logger.Warnf("GetThreatFlowByID(%s) failed, err:%v", flowId, err)
		return &v2.AttackFlowReply{}
	}

	ret := v2.AttackFlowReply{Relates: attackFlow.Relates}
	for _, item := range attackFlow.Fields {
		ret.Fields = append(ret.Fields, &v2.AttackFlowReply_Field{Item: item})
	}

	return &ret
}

// ListThreat 威胁事件列表
func (s *ADAServiceV2) ListThreat(ctx context.Context, in *v2.ListThreatReq) (*v2.ListThreatReply, error) {
	// page
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)

	var filter bson.D
	var err error
	if in.SearchType == 0 {
		filter, err = server.ThreatEventFilter(in.IDs, in.Level, in.EventStatus, in.StartTm, in.EndTm)
		if err != nil {
			logger.Errorf("therat event filter failed,err:%v", err)
			return nil, status.Errorf(codes.Internal, "解析检索条件异常")
		}
	} else {
		var req []server.AdvancedSearchReq
		for _, search := range in.AdvancedSearch {
			name := snakeString(search.Name)
			if len(search.Value) == 0 {
				continue
			}
			req = append(req, server.AdvancedSearchReq{
				Name:  name,
				Type:  search.Type,
				Value: search.Value,
			})
		}
		filter, err = server.AdvancedSearch(req)
		if err != nil {
			logger.Errorf("get advanced search failed,err:%v", err)
			return nil, status.Errorf(codes.Internal, "解析检索条件异常")
		}
	}

	events, total, err := server.FindThreatEventLikePattern(s.env, filter, in.SortTm, limit, offset)
	if err != nil {
		logger.Errorf("query list threat err:%v", err)
		return nil, status.Errorf(codes.Internal, "查询列表异常，请重试")
	}

	ret := v2.ListThreatReply{}

	for _, r := range events {
		ad, err := server.GetThreatDescByID(s.env, r.FlowId)
		if err != nil {
			logger.Errorf("GetThreatDescByID(%s) err:%v, will ignore this event!", r.FlowId, err)
			continue
		}
		eventTmpl := ad.EventTmplZH
		if s.language == bCommon.LangEn {
			eventTmpl = ad.EventTmplEN
		}

		ret.List = append(ret.List,
			&v2.ListThreatReply_Details{
				ID:          r.ID.Hex(),
				Title:       r.Title,
				Desc:        r.Desc,
				FlowId:      r.FlowId,
				AttckId:     r.AttCkId,
				Domain:      base.GetDomainFromHostname(r.DcHostname),
				DcHostname:  r.DcHostname,
				Level:       r.Level,
				Status:      r.Status,
				EventStatus: r.EventStatus,
				Remark:      r.Remark,
				Tags:        r.Tags,
				AttackFlow:  getAttackFlow(s.env, r.FlowId, r.FieldData),
				Duration:    int32(r.EndTs-r.StartTs) / 1000,
				EventTmpl:   eventTmpl,
				StartTm:     time.UnixMilli(r.StartTs).String(),
				EndTm:       time.UnixMilli(r.EndTs).String(),
			})
	}
	ret.Page = &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: int32(total)}
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}
	return &ret, nil
}

// GetThreat 威胁事件详情
func (s *ADAServiceV2) GetThreat(ctx context.Context, in *v2.GetThreatReq) (*v2.GetThreatReply, error) {
	if len(in.ID) != 24 {
		return nil, status.Errorf(codes.InvalidArgument, "无效ID")
	}
	ae, err := server.GetThreatEventByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("GetThreatEventByID(%s) err:%v", in.ID, err)
		return nil, status.Errorf(codes.Internal, "查询告警事件异常")
	}

	ad, err := server.GetThreatDescByID(s.env, ae.FlowId)
	if err != nil {
		logger.Errorf("GetThreatDescByID(%s) err:%v", in.ID, err)
		return nil, status.Errorf(codes.Internal, "查询告警事件异常")
	}

	var activities []*v2.ActivityDetails
	for _, activityId := range ae.ActivityIds {
		// 根据activityID获取activity
		aa, err := server.GetThreatActivityByID(s.env, activityId)
		if err != nil {
			logger.Warnf("find alert activity by id :%v", err)
			break
		}
		activities = append(activities, &v2.ActivityDetails{
			ID:             aa.ID.Hex(),
			Title:          aa.Title,
			Desc:           aa.Desc,
			RuleId:         aa.RuleId,
			UniqueId:       aa.UniqueId,
			AttckId:        aa.AttCkId,
			Level:          aa.Level,
			DcHostname:     aa.DcHostname,
			RuleConfidence: aa.Status,
			Tags:           aa.Tags,
			FieldData:      aa.FieldData,
			RawLog:         aa.RawLog,
			CreateTm:       aa.CreateTm.String(),
		})
	}

	eventTmpl := ad.EventTmplZH
	suggestion := ad.SuggestionZH
	verifyDesc := ad.VerifyDescZH
	if s.language == bCommon.LangEn {
		eventTmpl = ad.EventTmplEN
		suggestion = ad.SuggestionEN
		verifyDesc = ad.VerifyDescEN
	}

	ret := v2.GetThreatReply{
		ID:         ae.ID.Hex(),
		Title:      ae.Title,
		Desc:       ae.Desc,
		FlowId:     ae.FlowId,
		AttckId:    ae.AttCkId,
		UniqueId:   ae.UniqueId,
		Domain:     ae.DcHostname,
		DcHostname: ae.DcHostname,
		Level:      ae.Level,
		Status:     ae.Status,
		Tags:       ae.Tags,
		Activities: activities,
		Duration:   int32(ae.EndTs - ae.StartTs),
		StartTm:    time.UnixMilli(ae.StartTs).String(),
		EndTm:      time.UnixMilli(ae.EndTs).String(),
		FieldData:  ae.FieldData,
		AttackFlow: getAttackFlow(s.env, ae.FlowId, ae.FieldData),
		EventTmpl:  eventTmpl,
		Suggestion: suggestion,
		VerifyDesc: verifyDesc,
		Remark:     ae.Remark,
	}

	return &ret, nil
}

// ActionThreat 威胁事件操作: ignore/finish
func (s *ADAServiceV2) ActionThreat(ctx context.Context, in *v2.ActionThreatReq) (*v2.ActionThreatReply, error) {
	if len(in.ID) != 24 {
		return nil, status.Errorf(codes.InvalidArgument, "无效ID")
	}
	ae, err := server.GetThreatEventByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("GetThreatEventByID(%s) err:%v", in.ID, err)
		return nil, status.Errorf(codes.Internal, "无效ID")
	}

	if ae.EventStatus != common.RiskStatusPending {
		return nil, status.Errorf(codes.Internal, "事件已处理")
	}

	err = server.UpdateThreatEventStatus(s.env, in.ID, in.EventStatus, in.Remark)
	if err != nil {
		logger.Errorf("UpdateThreatEventStatus by id(%s) err:%v", in.ID, err)
		return nil, status.Errorf(codes.Internal, "更新失败")
	}

	return &v2.ActionThreatReply{Result: common.RESP_SUCCESS}, nil
}

// ListActivity 威胁行为列表
func (s *ADAServiceV2) ListActivity(ctx context.Context, in *v2.ListActivityReq) (*v2.ListActivityReply, error) {
	ret := &v2.ListActivityReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 1},
		Exhausted: true,
	}

	if in.ID != "" {
		// 根据activityID获取activity
		aa, err := server.GetThreatActivityByID(s.env, in.ID)
		if err != nil {
			logger.Errorf("find alert activity by id :%v", err)
			return ret, status.Errorf(codes.Internal, "查询告警行为异常")
		}
		ret.List = append(ret.List, &v2.ActivityDetails{
			ID:             aa.ID.Hex(),
			Title:          aa.Title,
			Desc:           aa.Desc,
			RuleId:         aa.RuleId,
			UniqueId:       aa.UniqueId,
			AttckId:        aa.AttCkId,
			Level:          aa.Level,
			RuleConfidence: aa.Status,
			DcHostname:     aa.DcHostname,
			Tags:           aa.Tags,
			FieldData:      aa.FieldData,
			RawLog:         aa.RawLog,
			CreateTm:       aa.CreateTm.String(),
		})
		return ret, nil
	}

	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)

	filter, err := server.ThreatActivityFilter(in.Level, in.DcHostname, in.Title, in.StartTm, in.EndTm)
	if err != nil {
		logger.Errorf("parse therat activity filter err:%v", err)
		return nil, status.Errorf(codes.Internal, "查询条件错误")
	}

	activities, total, err := server.FindThreatActivitySelect(s.env, filter, in.OrderCreateTm, limit, offset)
	if err != nil {
		logger.Errorf("find alert activity by event id :%v", err)
		return ret, status.Errorf(codes.Internal, "查询告警行为异常")
	}

	for _, aa := range activities {
		ret.List = append(ret.List, &v2.ActivityDetails{
			ID:             aa.ID.Hex(),
			Title:          aa.Title,
			Desc:           aa.Desc,
			RuleId:         aa.RuleId,
			UniqueId:       aa.UniqueId,
			AttckId:        aa.AttCkId,
			Level:          aa.Level,
			DcHostname:     aa.DcHostname,
			RuleConfidence: aa.Status,
			Tags:           aa.Tags,
			FieldData:      aa.FieldData,
			RawLog:         aa.RawLog,
			CreateTm:       aa.CreateTm.String(),
		})
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}
	return ret, nil
}

// GetActivityNames 威胁行为名称title list
func (s *ADAServiceV2) GetActivityNames(ctx context.Context, in *v2.GetActivityNamesReq) (*v2.GetActivityNamesReply, error) {
	names, err := server.GetThreatActivityAggNames(s.env, in.DcHostname, in.StartTm, in.EndTm)
	if err != nil {
		logger.Errorf("get threat activity names err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取告警行为名称失败")
	}

	return &v2.GetActivityNamesReply{Names: names}, nil
}

// GetActivity 威胁行为详情
func (s *ADAServiceV2) GetActivity(ctx context.Context, in *v2.GetActivityReq) (*v2.GetActivityReply, error) {
	if len(in.ID) != 24 {
		return nil, status.Errorf(codes.InvalidArgument, "无效ID")
	}

	// 根据activityID获取activity
	aa, err := server.GetThreatActivityByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("find alert activity by id :%v", err)
		return nil, status.Errorf(codes.Internal, "查询告警行为异常")
	}

	ret := v2.GetActivityReply{}
	ret.Details = &v2.ActivityDetails{
		ID:             aa.ID.Hex(),
		Title:          aa.Title,
		Desc:           aa.Desc,
		RuleId:         aa.RuleId,
		UniqueId:       aa.UniqueId,
		AttckId:        aa.AttCkId,
		Level:          aa.Level,
		DcHostname:     aa.DcHostname,
		RuleConfidence: aa.Status,
		Tags:           aa.Tags,
		FieldData:      aa.FieldData,
		RawLog:         aa.RawLog,
		CreateTm:       aa.CreateTm.String(),
	}

	return &ret, nil
}

func (s *ADAServiceV2) ListThreatRule(ctx context.Context, in *v2.ListThreatRuleReq) (*v2.ListThreatRuleReply, error) {
	descList, err := server.FindThreatDescSelect(s.env, in.Level, in.Enable)
	if err != nil {
		logger.Errorf("get all threat desc err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取规则名称失败")
	}

	var ret v2.ListThreatRuleReply
	for _, desc := range descList {
		var name, typ string
		if s.language == bCommon.LangEn {
			name = desc.NameEN
			typ = desc.TypeEN
		} else {
			name = desc.NameZH
			typ = desc.TypeZH
		}

		ret.List = append(ret.List, &v2.ListThreatRuleReply_Details{
			ID:        desc.ID,
			Name:      name,
			Type:      typ,
			Enable:    desc.Enable,
			AutoBlock: desc.AutoBlock,
			Level:     desc.Level,
			UpdateTm:  desc.UpdateTm.String(),
		})
	}

	return &ret, nil
}

func (s *ADAServiceV2) ActionThreatRule(ctx context.Context, in *v2.ActionThreatRuleReq) (*v2.ActionThreatRuleReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}
	if in.ID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "规则ID不能为空")
	}

	ret := v2.ActionThreatRuleReply{
		Result: common.RESP_FAILED,
	}

	err := server.UpdateThreatDesc(s.env, in.ID, in.Type, in.Switch)
	if err != nil {
		logger.Errorf("update threat desc err:%v", err)
		return nil, status.Errorf(codes.Internal, "更新规则状态失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

// GetThreatNames 返回威胁名称与ruleId的map列表
func (s *ADAServiceV2) GetThreatNames(ctx context.Context, in *v2.GetThreatNamesReq) (*v2.GetThreatNamesReply, error) {
	var mameMap = make(map[string]string)

	if in.RuleId != "" {
		desc, err := server.GetThreatDescByID(s.env, in.RuleId)
		if err != nil {
			logger.Errorf("get threat desc by id(%s) err:%v", in.RuleId, err)
			return nil, status.Errorf(codes.Internal, "获取威胁名称失败")
		}
		if s.language == bCommon.LangEn {
			mameMap[desc.ID] = desc.NameEN
		} else {
			mameMap[desc.ID] = desc.NameZH
		}

		return &v2.GetThreatNamesReply{Names: mameMap}, nil
	}

	descList, err := server.GetAllThreatDesc(s.env)
	if err != nil {
		logger.Errorf("get all threat desc err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取威胁名称失败")
	}

	for _, desc := range descList {
		if s.language == bCommon.LangEn {
			mameMap[desc.ID] = desc.NameEN
		} else {
			mameMap[desc.ID] = desc.NameZH
		}
	}

	return &v2.GetThreatNamesReply{Names: mameMap}, nil
}

// ListThreatConf 威胁配置列表
func (s *ADAServiceV2) ListThreatConf(ctx context.Context, in *v2.ListThreatConfReq) (*v2.ListThreatConfReply, error) {
	// TODO:
	return nil, nil
}

// UpdateThreatConf 更新威胁配置
func (s *ADAServiceV2) UpdateThreatConf(ctx context.Context, in *v2.UpdateThreatConfReq) (*v2.UpdateThreatConfReply, error) {
	// TODO:
	return nil, nil
}

// ListSensitiveEntry 敏感条目列表
func (s *ADAServiceV2) ListSensitiveEntry(ctx context.Context, in *v2.ListSensitiveEntryReq) (*v2.ListSensitiveEntryReply, error) {
	limit, offset := in.PageSize, (in.PageIdx-1)*in.PageSize
	entries, total, err := server.FindSensitiveEntryList(s.env, in.Type, in.Domain, in.Origin, in.StartTm, in.EndTm, in.OrderCreateTm, in.OrderUpdateTm, limit, offset)
	if err != nil {
		logger.Errorf("find sensitive entry list err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取敏感配置失败")
	}

	var ret v2.ListSensitiveEntryReply
	for _, entry := range entries {
		name, ok := entry.Content["name"]
		if !ok {
			continue
		}
		ret.List = append(ret.List, &v2.ListSensitiveEntryReply_Details{
			ID:       entry.ID.Hex(),
			Name:     name,
			Domain:   entry.Domain,
			Origin:   entry.Origin,
			CreateTm: entry.CreateTm.String(),
			UpdateTm: entry.UpdateTm.String(),
		})
	}

	ret.Page = &v2.ModelPage{
		PageIdx:  in.PageIdx,
		PageSize: in.PageSize,
		Total:    int32(total),
	}
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}

	return &ret, nil
}

// AddSensitiveEntry 增加敏感条目
func (s *ADAServiceV2) AddSensitiveEntry(ctx context.Context, in *v2.AddSensitiveEntryReq) (*v2.AddSensitiveEntryReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	if in.Domain == "" || in.Name == "" {
		return nil, status.Errorf(codes.InvalidArgument, "选择域和名称条目不能为空")
	}

	_, err := server.GetSensitiveEntryByName(s.env, in.Name, in.Type, in.Domain)
	if err == nil {
		return nil, status.Errorf(codes.InvalidArgument, "新增域列表已存在")
	}

	// TODO: get sid by entry name.
	var sid string

	err = server.AddSensitiveEntry(s.env, in.Name, sid, in.Type, in.Domain)
	if err != nil {
		logger.Errorf("add sensitive entry err:%v", err)
		return nil, status.Errorf(codes.Internal, "新增条目失败")
	}

	key := cache.SensitiveEntryKey(in.Domain, in.Type)
	err = s.env.RedisCli.SAdd(ctx, key, []string{in.Name}).Err()
	if err != nil {
		logger.Warnf("redis cli save sensitive entry cache err:%v", err)
		return nil, status.Errorf(codes.Internal, "新增条目缓存失败")
	}

	return &v2.AddSensitiveEntryReply{Result: common.RESP_SUCCESS}, nil
}

func (s *ADAServiceV2) ListDomainEntry(ctx context.Context, in *v2.ListDomainEntryReq) (*v2.ListDomainEntryReply, error) {
	if in.Type != "user" {
		return nil, status.Errorf(codes.InvalidArgument, "类型错误,当前仅支持user")
	}

	var err error
	var entries []string
	switch in.Type {
	case "user":
		entries, err = server.FindDomainEntryUser(s.env, in.Domain, in.Search)
	case "group":
		entries, err = server.FindDomainEntryGroup(s.env, in.Domain, in.Search)
	case "computer":
		entries, err = server.FindDomainEntryComputer(s.env, in.Domain, in.Search)
	}
	if err != nil {
		logger.Errorf("find domain entry err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取域内Entry失败")
	}

	return &v2.ListDomainEntryReply{
		Entries: entries,
	}, nil
}

// DeleteSensitiveEntry 删除敏感条目
func (s *ADAServiceV2) DeleteSensitiveEntry(ctx context.Context, in *v2.DeleteSensitiveEntryReq) (*v2.DeleteSensitiveEntryReply, error) {
	ret := v2.DeleteSensitiveEntryReply{Result: RESP_FAILED}

	if !s.IsSuper(ctx) {
		return &ret, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	entry, err := server.GetSensitiveEntryById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get sensitive entry by id(%s) err:%v", in.ID, err)
		return &ret, status.Errorf(codes.Internal, "获取条目失败")
	}

	if name, ok := entry.Content["name"]; ok {
		key := cache.SensitiveEntryKey(entry.Domain, entry.Type)
		err = s.env.RedisCli.SRem(ctx, key, []string{name}).Err()
		if err != nil {
			logger.Warnf("redis cli delete sensitive entry cache err:%v", err)
			return &ret, status.Errorf(codes.Internal, "删除条目缓存失败")
		}
	}

	err = server.DeleteSensitiveEntry(s.env, in.ID)
	if err != nil {
		logger.Errorf("delete sensitive entry err:%v", err)
		return &ret, status.Errorf(codes.Internal, "删除条目失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

// ThreatTops 威胁Top: 告警事件/告警行为top10
func (s *ADAServiceV2) ThreatTops(ctx context.Context, in *v2.ThreatTopsReq) (*v2.ThreatTopsReply, error) {
	results, err := server.ThreatTops(s.env, in.Domain, in.Type, in.Duration)
	if err != nil {
		logger.Errorf("get threat tops err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取失败")
	}

	var ret v2.ThreatTopsReply
	for _, item := range results {
		// item: primitive.M{\"_id\":\"process creation via command in terminal\", \"count\":34230}
		ret.List = append(ret.List, &v2.ThreatTopsReply_Details{
			Name:  item["_id"].(string),
			Total: item["count"].(int32),
		})
	}

	return &ret, nil
}

// ThreatTops 告警行为趋势
func (s *ADAServiceV2) ThreatTrends(ctx context.Context, in *v2.ThreatTrendsReq) (*v2.ThreatTrendsReply, error) {
	results, err := server.ThreatTrends(s.env, in.Domain, in.Level, in.Duration)
	if err != nil {
		logger.Errorf("get threat trends err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取失败")
	}

	var ret v2.ThreatTrendsReply
	for _, item := range results {
		// item: primitive.M{\"_id\":\"process creation via command in terminal\", \"count\":34230}
		ret.List = append(ret.List, &v2.ThreatTrendsReply_Item{
			Ts:    item["_id"].(int64),
			Total: item["count"].(int32),
		})
	}

	return &ret, nil
}

// ListThreatWhitelist 威胁白名单列表
func (s *ADAServiceV2) ListThreatWhitelist(ctx context.Context, in *v2.ListThreatWhitelistReq) (*v2.ListThreatWhitelistReply, error) {
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)

	whitelist, total, err := server.FindAllThreatWhitelist(s.env, in.RuleId, in.Domain, in.Origin, in.Search, in.StartTm, in.EndTm, in.OrderUpdateTm, int64(limit), int64(offset))
	if err != nil {
		logger.Errorf("query whitelist err:%v", err)
		return nil, status.Errorf(codes.Internal, "查询失败")
	}

	var ret v2.ListThreatWhitelistReply
	for _, w := range whitelist {
		rules := make([]*v2.ListThreatWhitelistReply_DetailsRuleInfo, 0)
		for _, r := range w.RuleInfo {
			rules = append(rules, &v2.ListThreatWhitelistReply_DetailsRuleInfo{Info: r})
		}

		ret.List = append(ret.List, &v2.ListThreatWhitelistReply_Details{
			ID:       w.ID.Hex(),
			RuleId:   w.RuleId,
			RuleName: w.RuleName,
			RuleType: w.RuleType,
			Rules:    rules,
			Domain:   w.Domain,
			Origin:   w.Origin,
			Remark:   w.Remark,
			CreateTm: w.CreateTm.String(),
			UpdateTm: w.UpdateTm.String(),
		})

	}

	ret.Page = &v2.ModelPage{
		PageIdx:  in.PageIdx,
		PageSize: in.PageSize,
		Total:    int32(total),
	}
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}

	return &ret, nil
}

func (s *ADAServiceV2) GetThreatWhitelistField(ctx context.Context, in *v2.GetThreatWhitelistFieldReq) (*v2.GetThreatWhitelistFieldReply, error) {
	_, err := server.GetThreatDescByID(s.env, in.RuleId)
	if err != nil {
		logger.Errorf("get threat desc by id(%s) err:%v", in.RuleId, err)
		return nil, status.Errorf(codes.Internal, "获取规则失败")
	}

	fields, err := getThreatWhitelistFields(ctx, s.env, in.RuleId)
	if err != nil {
		logger.Errorf("get threat whitelist fields err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取规则字段失败")
	}

	return &v2.GetThreatWhitelistFieldReply{Fields: fields}, err
}

func (s *ADAServiceV2) AddThreatWhitelist(ctx context.Context, in *v2.AddThreatWhitelistReq) (*v2.AddThreatWhitelistReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	var ret = v2.AddThreatWhitelistReply{
		Result: common.RESP_FAILED,
	}

	rule, err := server.GetThreatDescByID(s.env, in.RuleId)
	if err != nil {
		logger.Errorf("get threat desc by id(%s) err:%v", in.RuleId, err)
		return &ret, status.Errorf(codes.Internal, "获取规则失败")
	}

	// get rule fields from redis
	fields, err := getThreatWhitelistFields(ctx, s.env, in.RuleId)
	if err != nil {
		logger.Errorf("get threat whitelist fields err:%v", err)
		return &ret, status.Errorf(codes.Internal, "获取规则字段失败")
	}

	var rules []map[string]string
	for _, r := range in.Rules {
		// 进行字段校验,确保各字段有效，提高engine侧处理效率
		ok, errStr := checkThreatWhitelistFields(r.Info, fields)
		if !ok {
			return &ret, status.Errorf(codes.InvalidArgument, errStr)
		}

		rules = append(rules, r.Info)
	}

	ruleCnt, ruleMd5 := sortAndHashRuleInfo(in.Domain, rules)

	// check if this rule already exists
	if checkThreatWhitelistExist(ctx, s.env, in.RuleId, ruleMd5) {
		return &ret, status.Errorf(codes.InvalidArgument, "规则已存在")
	}

	var wId string
	if s.language == bCommon.LangEn {
		wId, err = server.AddThreatWhitelist(s.env, rule.ID, rule.NameEN, rule.TypeEN, in.Domain, in.Remark, in.Origin, rules)
	} else {
		wId, err = server.AddThreatWhitelist(s.env, rule.ID, rule.NameZH, rule.TypeZH, in.Domain, in.Remark, in.Origin, rules)
	}
	if err != nil {
		logger.Errorf("delete whitelist err:%v", err)
		return &ret, status.Errorf(codes.Internal, "删除失败")
	}

	// update whitelist cache in redis, for engine.
	whitelistKey := fmt.Sprintf("%s:%s", cache.FlowWhitelistPrefixKey, in.RuleId)
	err = s.env.RedisCli.HSetNX(ctx, whitelistKey, wId, ruleCnt).Err()
	if err != nil && err != redis.Nil {
		logger.Errorf("set threat whitelist fields from redis err:%v", err)
		return &ret, status.Errorf(codes.Internal, "删除失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) UpdateThreatWhitelist(ctx context.Context, in *v2.UpdateThreatWhitelistReq) (*v2.UpdateThreatWhitelistReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	var ret = v2.UpdateThreatWhitelistReply{
		Result: common.RESP_FAILED,
	}

	wl, err := server.GetThreatWhitelistById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get threat whitelist by id(%s) err:%v", in.ID, err)
		return &ret, status.Errorf(codes.Internal, "获取规则失败")
	}

	// get rule fields from redis
	fields, err := getThreatWhitelistFields(ctx, s.env, wl.RuleId)
	if err != nil {
		logger.Errorf("get threat whitelist fields err:%v", err)
		return &ret, status.Errorf(codes.Internal, "获取规则字段失败")
	}

	// update whitelist cache in redis, for engine.
	var rules []map[string]string
	for _, r := range in.Rules {
		// 进行字段校验,确保各字段有效，提高engine侧处理效率
		ok, errStr := checkThreatWhitelistFields(r.Info, fields)
		if !ok {
			return &ret, status.Errorf(codes.InvalidArgument, errStr)
		}

		rules = append(rules, r.Info)
	}

	ruleCnt, ruleMd5 := sortAndHashRuleInfo(wl.Domain, rules)

	// check if this rule already exists
	if checkThreatWhitelistExist(ctx, s.env, wl.RuleId, ruleMd5) {
		return &ret, status.Errorf(codes.InvalidArgument, "规则已存在")
	}

	// update whitelist cache in redis, for engine.

	whitelistKey := fmt.Sprintf("%s:%s", cache.FlowWhitelistPrefixKey, wl.RuleId)
	err = s.env.RedisCli.HSetNX(ctx, whitelistKey, wl.ID.Hex(), ruleCnt).Err()
	if err != nil && err != redis.Nil {
		logger.Errorf("set threat whitelist into redis err:%v", err)
		return &ret, status.Errorf(codes.Internal, "更新规则缓存失败")
	}

	err = server.UpdateThreatWhitelist(s.env, in.ID, in.Remark, rules)
	if err != nil {
		logger.Errorf("update whitelist(ruleId:%s,wId:%s) err:%v", wl.RuleId, in.ID, err)
		return &ret, status.Errorf(codes.Internal, "更新规则白名单失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) DeleteThreatWhitelist(ctx context.Context, in *v2.DeleteThreatWhitelistReq) (*v2.DeleteThreatWhitelistReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	var ret = v2.DeleteThreatWhitelistReply{
		Result: common.RESP_FAILED,
	}

	wl, err := server.GetThreatWhitelistById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get threat whitelist by id(%s) err:%v", in.ID, err)
		return &ret, status.Errorf(codes.Internal, "获取规则失败")
	}

	// delete whitelist cache in redis, for engine.
	whitelistKey := fmt.Sprintf("%s:%s", cache.FlowWhitelistPrefixKey, wl.RuleId)
	err = s.env.RedisCli.HDel(ctx, whitelistKey, in.ID).Err()
	if err != nil {
		logger.Errorf("del whitelist(ruleId:%s, wId:%s) from redis err:%v", wl.RuleId, in.ID, err)
		return &ret, status.Errorf(codes.Internal, "删除规则缓存失败")
	}

	err = server.DeleteThreatWhitelist(s.env, in.ID)
	if err != nil {
		logger.Errorf("delete whitelist err:%v", err)
		return &ret, status.Errorf(codes.Internal, "删除失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func getThreatWhitelistFields(ctx context.Context, env *config.Env, ruleId string) ([]string, error) {
	// engine侧将每个规则中的fields字段存储到redis中，这里直接从redis中获取

	fieldStr, err := env.RedisCli.HGet(ctx, cache.FlowFieldMapKey, ruleId).Result()
	if err != nil && err != redis.Nil {
		logger.Errorf("get threat whitelist fields from redis err:%v", err)
		return nil, err
	}
	return strings.Split(fieldStr, ","), err
}

func sortAndHashRuleInfo(domain string, ruleInfo []map[string]string) (string, string) {
	// 将ruleInfo []map[string]string 转换为字符串，然后进行MD5计算，与redis中的MD5值进行比对
	// 按照每个 map[string]string 中的field进行排序，然后拼接成字符串,再进行MD5计算

	var keys []string
	var keyIdxMap = make(map[string]int)
	for idx, item := range ruleInfo {
		field := item["field"]
		keyIdxMap[field] = idx
		keys = append(keys, field)
	}
	sort.Strings(keys)
	var ruleItem []string
	for _, k := range keys {
		idx := keyIdxMap[k]
		r := ruleInfo[idx]
		ruleItem = append(ruleItem, fmt.Sprintf("%s,%s,%s", r["field"], r["op"], r["value"]))
	}

	ruleCnt := fmt.Sprintf("%s||%s", strings.ToLower(domain), strings.Join(ruleItem, "|[AND]|"))
	ruleMd5 := crypto.MD5String(ruleCnt, 32)

	return ruleCnt, ruleMd5
}

func checkThreatWhitelistExist(ctx context.Context, env *config.Env, ruleId string, ruleMd5 string) bool {
	whiteKey := fmt.Sprintf("%s:%s", cache.FlowWhitelistPrefixKey, ruleId)
	whitelists, err := env.RedisCli.HGetAll(ctx, whiteKey).Result()
	if err != nil {
		logger.Errorf("get whitelist from redis err:%v, will bypass whitelist!", err)
		return false
	}

	for _, rule := range whitelists {
		t := crypto.MD5String(rule, 32)
		logger.Debugf("tmp:%s, ruleCnt:%s", t, rule)
		if t == ruleMd5 {
			return true
		}
	}

	return false
}

func checkThreatWhitelistFields(ruleInfo map[string]string, fields []string) (bool, string) {
	if len(ruleInfo) == 0 {
		return false, "无效的规则"
	}
	filed, ok := ruleInfo["field"]
	if !ok {
		return false, "规则字段field不存在"
	}
	if !base.InArray(filed, fields) {
		return false, fmt.Sprintf("无效的规则字段field:%s", filed)
	}

	op, ok := ruleInfo["op"]
	if !ok {
		return false, "规则字段op不存在"
	}
	if !base.InArray(op, []string{"==", "!=", ">", "<", ">=", "<=", "in", "not_in", "contain", "not_contain", "regex"}) {
		return false, fmt.Sprintf("无效的规则字段op:%s", op)
	}

	value, ok := ruleInfo["value"]
	if !ok {
		return false, "规则字段value不存在"
	}
	if strings.Contains(value, "[AND]") {
		return false, fmt.Sprintf("不合法的规则字段value:%s", value)
	}
	if op == "regex" {
		_, err := regexp.Compile(value)
		if err != nil {
			return false, fmt.Sprintf("不合法的正则表达式:%s", value)
		}
	}

	return true, ""
}

// 阻断策略
func (s *ADAServiceV2) ListThreatBlock(ctx context.Context, in *v2.ListThreatBlockReq) (*v2.ListThreatBlockReply, error) {
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)

	policies, total, err := server.FindAllThreatBlock(s.env, in.Domain, in.Origin, in.Search, in.StartTm, in.EndTm, int64(limit), int64(offset))
	if err != nil {
		logger.Errorf("query block policy err:%v", err)
		return nil, status.Errorf(codes.Internal, "查询失败")
	}

	var ret v2.ListThreatBlockReply
	for _, p := range policies {
		var results []*v2.ListThreatBlockReply_Results
		for _, r := range p.Result {
			results = append(results, &v2.ListThreatBlockReply_Results{Info: r})
		}

		ret.List = append(ret.List, &v2.ListThreatBlockReply_Details{
			ID:        p.ID.Hex(),
			Name:      p.Name,
			Domain:    p.Domain,
			Origin:    p.Origin,
			UserBlock: p.UserBlock,
			IpBlock:   p.IpBlock,
			UserList:  p.UserList,
			IpList:    p.IpList,
			Results:   results,
			Remark:    p.Remark,
			CreateTm:  p.CreateTm.String(),
			UpdateTm:  p.UpdateTm.String(),
		})
	}

	ret.Page = &v2.ModelPage{
		PageIdx:  in.PageIdx,
		PageSize: in.PageSize,
		Total:    int32(total),
	}
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	} else {
		ret.Exhausted = true
	}

	return &ret, nil
}

func (s *ADAServiceV2) AddThreatBlock(ctx context.Context, in *v2.AddThreatBlockReq) (*v2.AddThreatBlockReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	var ret = v2.AddThreatBlockReply{
		Result: common.RESP_FAILED,
	}

	if checkSensorOffline(s.env, in.Domain) {
		return &ret, status.Errorf(codes.Canceled, "域名下的传感器全部离线")
	}

	if in.IpBlock && len(in.IpList) == 0 {
		return &ret, status.Errorf(codes.InvalidArgument, "IP阻断列表不能为空")
	}
	if in.UserBlock && len(in.UserList) == 0 {
		return &ret, status.Errorf(codes.InvalidArgument, "用户阻断列表不能为空")
	}

	sensors, err := server.FindAllSensorByDomain(s.env, in.Domain)
	if err != nil {
		logger.Errorf("get domain by name(%s) err:%v", in.Domain, err)
		return &ret, status.Errorf(codes.InvalidArgument, "域名不存在")
	}

	var results []map[string]string // 阻断结果

	var adaMsg sCommon.AdaMessage

	for _, sensor := range sensors {
		var cmdData = make(map[string]string)
		var result = make(map[string]string) // {"dc_hostname":"dc01.xx","ip_list/user_list":"xx,xx","msg":"ok","time":"xx"}

		result["dc_hostname"] = sensor.DCHostName
		result["time"] = time.Now().Format("2006-01-02 15:04:05")

		if in.UserBlock {
			cmdData["user_add"] = strings.Join(in.UserList, ",")
			result["user_list"] = cmdData["user_add"]
		}
		if in.IpBlock {
			cmdData["ip_add"] = strings.Join(in.IpList, ",")
			result["ip_list"] = cmdData["ip_add"]
		}

		if sensor.Status == sCommon.SensorStatusStop {
			logger.Warnf("sensor(%s) is stop, skip push threat policy!", sensor.ID)
			result["msg"] = "offline"
			results = append(results, result)
			continue
		}

		adaMsg.AgentID = sensor.ID
		adaMsg.Data = cmdData
		err = pushThreatPolicy(ctx, s.env.RedisCli, adaMsg)
		if err != nil {
			logger.Errorf("push blocking policy to sensor(%s) err:%v", sensor.ID, err)
			result["msg"] = "push policy failed"
			results = append(results, result)
			continue
		}

		result["msg"] = "ok"
		results = append(results, result)
	}

	err = server.AddThreatBlock(s.env, in.Name, in.Domain, in.Remark, in.UserBlock, in.IpBlock, in.UserList, in.IpList, results)
	if err != nil {
		logger.Errorf("add block policy err:%v", err)
		return &ret, status.Errorf(codes.Internal, "新增失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) UpdateThreatBlock(ctx context.Context, in *v2.UpdateThreatBlockReq) (*v2.UpdateThreatBlockReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	var ret = v2.UpdateThreatBlockReply{
		Result: common.RESP_FAILED,
	}

	ab, err := server.GetThreatBlock(s.env, in.ID)
	if err != nil {
		logger.Errorf("get block policy by id(%s) err:%v", in.ID, err)
		return &ret, status.Errorf(codes.Internal, "获取失败")
	}

	if checkSensorOffline(s.env, ab.Domain) {
		return &ret, status.Errorf(codes.Canceled, "域名下的传感器全部离线")
	}

	var cmdData = make(map[string]string)

	// Compare UserList
	if in.UserBlock {
		oldUsers := make(map[string]bool)
		for _, user := range ab.UserList {
			oldUsers[user] = true
		}

		var userAdd, userDel []string
		for _, user := range in.UserList {
			if !oldUsers[user] {
				userAdd = append(userAdd, user)
			}
			delete(oldUsers, user)
		}
		for user := range oldUsers {
			userDel = append(userDel, user)
		}

		if len(userAdd) > 0 {
			cmdData["user_add"] = strings.Join(userAdd, ",")
		}
		if len(userDel) > 0 {
			cmdData["user_del"] = strings.Join(userDel, ",")
		}
	} else {
		// update in.UserList = []string{}
		in.UserList = []string{}
		cmdData["user_del"] = strings.Join(ab.UserList, ",")
	}

	// Compare IpList
	if in.IpBlock {
		oldIPs := make(map[string]bool)
		for _, ip := range ab.IpList {
			oldIPs[ip] = true
		}

		var ipAdd, ipDel []string
		for _, ip := range in.IpList {
			if !oldIPs[ip] {
				ipAdd = append(ipAdd, ip)
			}
			delete(oldIPs, ip)
		}
		for ip := range oldIPs {
			ipDel = append(ipDel, ip)
		}

		if len(ipAdd) > 0 {
			cmdData["ip_add"] = strings.Join(ipAdd, ",")
		}
		if len(ipDel) > 0 {
			cmdData["ip_del"] = strings.Join(ipDel, ",")
		}
	} else {
		// update in.IpList = []string{}
		in.IpList = []string{}
		cmdData["ip_del"] = strings.Join(ab.IpList, ",")
	}

	if len(cmdData) == 0 {
		return &ret, status.Errorf(codes.InvalidArgument, "没有变化")
	}

	var results []map[string]string // 阻断结果
	var adaMsg sCommon.AdaMessage

	// Push updates to sensors
	for _, item := range ab.Result {
		dcHostname, ok := item["dc_hostname"]
		if !ok {
			continue
		}

		var result = make(map[string]string) // {"dc_hostname":"dc01.xx","ip_list/user_list":"xx,xx","msg":"ok","time":"xx"}
		result["dc_hostname"] = dcHostname
		result["time"] = time.Now().Format("2006-01-02 15:04:05")
		result["user_list"] = ""
		result["ip_list"] = ""

		if in.UserBlock {
			result["user_list"] = strings.Join(in.UserList, ",")
		}
		if in.IpBlock {
			result["ip_list"] = strings.Join(in.IpList, ",")
		}

		sensorIns, err := server.GetSensorByDcHostName(s.env, dcHostname)
		if err != nil {
			logger.Errorf("get sensor by dc hostname(%s) err:%v", dcHostname, err)
			result["msg"] = fmt.Sprintf("get sensor(%s) err:%v", dcHostname, err)
			results = append(results, result)
			continue
		}

		if sensorIns.Status == sCommon.SensorStatusStop {
			logger.Warnf("sensor(%s) is stop, skip push threat policy!", sensorIns.ID)
			result["msg"] = "offline"
			results = append(results, result)
			continue
		}

		adaMsg.AgentID = sensorIns.ID
		adaMsg.Data = cmdData

		err = pushThreatPolicy(ctx, s.env.RedisCli, adaMsg)
		if err != nil {
			logger.Errorf("push threat blocking policy err:%v", err)
			result["msg"] = "push policy failed"
			results = append(results, result)
			continue
		}

		result["msg"] = "ok"
		results = append(results, result)
	}

	err = server.UpdateThreatBlock(s.env, in.ID, in.Name, in.Remark, in.UserBlock, in.IpBlock, in.UserList, in.IpList, results)
	if err != nil {
		logger.Errorf("update block policy err:%v", err)
		return &ret, status.Errorf(codes.Internal, "更新失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) DeleteThreatBlock(ctx context.Context, in *v2.DeleteThreatBlockReq) (*v2.DeleteThreatBlockReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.PermissionDenied, "没有操作权限")
	}

	var ret = v2.DeleteThreatBlockReply{
		Result: common.RESP_FAILED,
	}

	ab, err := server.GetThreatBlock(s.env, in.ID)
	if err != nil {
		logger.Errorf("get block policy by id(%s) err:%v", in.ID, err)
		return &ret, status.Errorf(codes.Internal, "获取失败")
	}

	if checkSensorOffline(s.env, ab.Domain) {
		return &ret, status.Errorf(codes.Canceled, "域名下的传感器全部离线")
	}

	var adaMsg sCommon.AdaMessage

	var cmdData = make(map[string]string)
	for _, item := range ab.Result {
		dcHostname, ok := item["dc_hostname"]
		if !ok {
			continue
		}

		sensorIns, err := server.GetSensorByDcHostName(s.env, dcHostname)
		if err != nil {
			logger.Errorf("get sensor by dc hostname(%s) err:%v", dcHostname, err)
			continue
		}

		if sensorIns.Status == sCommon.SensorStatusStop {
			logger.Warnf("sensor(%s) is stop, skip push threat policy!", sensorIns.ID)
			continue
		}

		ipList, ok := item["ip_list"]
		if !ok {
			continue
		}
		cmdData["ip_del"] = ipList

		userList, ok := item["user_list"]
		if !ok {
			continue
		}
		cmdData["user_del"] = userList
		adaMsg.AgentID = sensorIns.ID
		adaMsg.Data = cmdData
		err = pushThreatPolicy(ctx, s.env.RedisCli, adaMsg)
		if err != nil {
			logger.Errorf("push blocking policy to sensor(%s) err:%v", sensorIns.ID, err)
			continue
		}
	}

	err = server.DeleteThreatBlock(s.env, in.ID)
	if err != nil {
		logger.Errorf("delete block policy err:%v", err)
		return &ret, status.Errorf(codes.Internal, "删除失败")
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func checkSensorOffline(env *config.Env, domain string) bool {
	sensors, err := server.FindAllSensorByDomain(env, domain)
	if err != nil {
		logger.Errorf("get domain by name(%s) err:%v", domain, err)
		return true
	}

	// check if all the sensor is offline
	anySensorOnline := false
	for _, sensor := range sensors {
		if sensor.Status != sCommon.SensorStatusStop {
			anySensorOnline = true
			break
		}
	}
	return !anySensorOnline
}

func pushThreatPolicy(ctx context.Context, rdxCli *redis.Client, cmdMsg sCommon.AdaMessage) error {
	cmdData := cmdMsg.Data
	_, ok := cmdData["user_add"]
	if !ok {
		cmdData["user_add"] = ""
	}
	_, ok = cmdData["ip_add"]
	if !ok {
		cmdData["ip_add"] = ""
	}
	_, ok = cmdData["user_del"]
	if !ok {
		cmdData["user_del"] = ""
	}
	_, ok = cmdData["ip_del"]
	if !ok {
		cmdData["ip_del"] = ""
	}

	cmdMsg.TaskID = strings.ReplaceAll(uuid.NewString(), "-", "")
	cmdMsg.Timestamp = time.Now().Unix()
	cmdMsg.MsgType = sCommon.T_PLUG_BLOCK_UPDATE
	cmdMsg.Version = version.BuildVersion

	cmdStr, err := jsoniter.MarshalToString(cmdMsg)
	if err != nil {
		logger.Errorf("json marshal failed: %v", err)
		return err
	}

	logger.Debugf("push blocking policy to sensor(%s),task_id:%s, cmd:%v", cmdMsg.AgentID, cmdMsg.TaskID, cmdStr)

	// publish config to agent(redis)
	err = rdxCli.Publish(ctx, sCommon.SensorCmdChannel, cmdStr).Err()
	if err != nil {
		logger.Errorf("redis public err:%v", err)
		return err
	}

	// 同步等待 下发结果
	taskSucc := false
	taskKey := fmt.Sprintf("%s_%s", sCommon.SensorCmdRespKey, cmdMsg.TaskID)
	for i := 0; i < 10; i++ {
		time.Sleep(1 * time.Second)
		succ := rdxCli.HGet(ctx, taskKey, "succeed").Val()
		if succ == "" {
			continue
		}
		if succ == "1" {
			// task succeed
			taskSucc = true
			break
		}
	}
	if !taskSucc {
		logger.Errorf("sync task result fialed or timeout, task_id:%s, sensor_id:%s", cmdMsg.TaskID, cmdMsg.AgentID)
		errMsg := rdxCli.HGet(ctx, taskKey, "msg").Val()
		return fmt.Errorf("sync task err_msg:%s", errMsg)
	}

	logger.Debugf("sync task result succeed, task_id:%s, sensor_id:%s", cmdMsg.TaskID, cmdMsg.AgentID)

	return nil
}
