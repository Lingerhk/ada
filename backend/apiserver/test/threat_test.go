package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"testing"
)

func TestListThreat(t *testing.T) {
	req := v2.ListThreatReq{
		PageSize:    10,
		PageIdx:     1,
		SearchType:  0,
		SortTm:      1,
		Level:       []int32{1, 2, 3, 4, 5},
		EventStatus: 1,
	}
	resp, err := ADACli.cli.ListThreat(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	//t.Logf("%#v", resp)
	for _, item := range resp.List {
		t.Logf("threat details:%#v", item)
		t.Logf("attack_flow, relates:%v", item.AttackFlow.Relates)
		for idx, field := range item.AttackFlow.Fields {
			t.Logf("attack_flow, field[%d]:%#v", idx, field)
		}
	}
}

func TestGetThreat(t *testing.T) {
	req := v2.GetThreatReq{
		ID: "66176c29852ef3e39d196cc9",
	}
	resp, err := ADACli.cli.GetThreat(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestActionThreat(t *testing.T) {
	req := v2.ActionThreatReq{
		ID:          "66a4dcb85aa8302e67ca803b",
		EventStatus: 1,
	}
	resp, err := ADACli.cli.ActionThreat(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestListActivity(t *testing.T) {
	req := v2.ListActivityReq{
		PageSize:      10,
		PageIdx:       1,
		OrderCreateTm: 1,
		Level:         []int32{1, 2, 3},
	}
	resp, err := ADACli.cli.ListActivity(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
	for _, item := range resp.List {
		t.Logf("activity details:%#v", item)
	}
}

func TestGetActivity(t *testing.T) {
	req := v2.GetActivityReq{
		ID: "66176c29852ef3e39d196cc7",
	}
	resp, err := ADACli.cli.GetActivity(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp.Details)
}

func TestListSensitiveEntry(t *testing.T) {
	req := v2.ListSensitiveEntryReq{
		PageIdx:  1,
		PageSize: 10,
		Type:     "user",
	}
	resp, err := ADACli.cli.ListSensitiveEntry(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("activity details:%#v", item)
	}
}

func TestAddSensitiveEntry(t *testing.T) {
	req := v2.AddSensitiveEntryReq{
		Type:   "user",
		Domain: "china.com",
		Name:   "test01",
	}
	resp, err := ADACli.cli.AddSensitiveEntry(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestDeleteSensitiveEntry(t *testing.T) {
	req := v2.DeleteSensitiveEntryReq{
		ID: "6618e489d41870efa21f7e81",
	}
	resp, err := ADACli.cli.DeleteSensitiveEntry(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestThreatTops(t *testing.T) {
	req := v2.ThreatTopsReq{
		Domain:   "china.com", // all|domainX
		Type:     "activity",
		Duration: 120,
	}
	resp, err := ADACli.cli.ThreatTops(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestThreatTrends(t *testing.T) {
	req := v2.ThreatTrendsReq{
		Domain:   "all", // all|domainX
		Level:    []int32{5, 4, 3, 2},
		Duration: 120,
	}
	resp, err := ADACli.cli.ThreatTrends(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestAddThreatWhitelist(t *testing.T) {
	var rules []*v2.AddThreatWhitelistReqRuleInfo
	rules = append(rules, &v2.AddThreatWhitelistReqRuleInfo{Info: map[string]string{"field": "IpAddress", "op": "!=", "value": "192.168.18.4"}})
	rules = append(rules, &v2.AddThreatWhitelistReqRuleInfo{Info: map[string]string{"field": "TargetUserName", "op": "==", "value": "Administrator"}})

	req := v2.AddThreatWhitelistReq{
		Domain: "china.com",
		RuleId: "flow-0005",
		Rules:  rules,
		Remark: "this is a test",
	}
	resp, err := ADACli.cli.AddThreatWhitelist(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestListThreatWhitelist(t *testing.T) {
	req := v2.ListThreatWhitelistReq{
		PageSize: 10,
		PageIdx:  1,
		Domain:   []string{"china.com"},
		//Search: "用户",
		RuleId: "flow-0001",
	}
	resp, err := ADACli.cli.ListThreatWhitelist(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("whitelist info:%#v", item)
	}
}

func TestUpdateThreatWhitelist(t *testing.T) {
	var rules []*v2.UpdateThreatWhitelistReqRuleInfo
	rules = append(rules, &v2.UpdateThreatWhitelistReqRuleInfo{Info: map[string]string{"field": "TargetUserName", "op": "==", "value": "Administrator"}})
	rules = append(rules, &v2.UpdateThreatWhitelistReqRuleInfo{Info: map[string]string{"field": "IpAddress", "op": "==", "value": "192.168.18.5"}})

	req := v2.UpdateThreatWhitelistReq{
		ID:     "66a6f0bda550f06f27c8e5d6",
		Rules:  rules,
		Remark: "this is a new remark",
	}
	resp, err := ADACli.cli.UpdateThreatWhitelist(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestDeleteThreatWhitelist(t *testing.T) {
	req := v2.DeleteThreatWhitelistReq{
		ID: "66a6f0bda550f06f27c8e5d6",
	}
	resp, err := ADACli.cli.DeleteThreatWhitelist(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestGetThreatWhitelistField(t *testing.T) {
	req := v2.GetThreatWhitelistFieldReq{
		RuleId: "flow-0005",
	}
	resp, err := ADACli.cli.GetThreatWhitelistField(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestGetThreatNames(t *testing.T) {
	req := v2.GetThreatNamesReq{
		//RuleId: "flow-0005",
	}
	resp, err := ADACli.cli.GetThreatNames(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestListThreatDesc(t *testing.T) {
	req := v2.ListThreatRuleReq{
		Level:  []int32{5, 4, 3, 2},
		Enable: []bool{true, false},
	}
	resp, err := ADACli.cli.ListThreatRule(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("threat desc info:%#v", item)
	}
}

func TestActionThreatRule(t *testing.T) {
	req := v2.ActionThreatRuleReq{
		ID:     "flow-0005",
		Type:   "auto_block",
		Switch: true,
	}
	resp, err := ADACli.cli.ActionThreatRule(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestListDomainEntry(t *testing.T) {
	req := v2.ListDomainEntryReq{
		Type:   "user",
		Domain: "china.com",
	}
	resp, err := ADACli.cli.ListDomainEntry(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestGetActivityNames(t *testing.T) {
	req := v2.GetActivityNamesReq{}
	resp, err := ADACli.cli.GetActivityNames(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestAddThreatBlock(t *testing.T) {
	req := v2.AddThreatBlockReq{
		Name:      "test02",
		Domain:    "china.com",
		Remark:    "this is a test2",
		UserBlock: true,
		IpBlock:   true,
		UserList:  []string{"admin"},
		IpList:    []string{"192.168.19.20", "192.168.19.21"},
	}
	resp, err := ADACli.cli.AddThreatBlock(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestUpdateThreatBlock(t *testing.T) {
	req := v2.UpdateThreatBlockReq{
		ID:     "66a6f0bda550f06f27c8e5d6",
		Name:   "test01",
		Remark: "this is a new remark",
	}
	resp, err := ADACli.cli.UpdateThreatBlock(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestDeleteThreatBlock(t *testing.T) {
	req := v2.DeleteThreatBlockReq{
		ID: "66e058fd08a979481953c9b5",
	}
	resp, err := ADACli.cli.DeleteThreatBlock(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestListThreatBlock(t *testing.T) {
	req := v2.ListThreatBlockReq{
		PageIdx:  1,
		PageSize: 10,
		Domain:   []string{"china.com"},
		Origin:   []int32{1, 2},
		//StartTm:  "2022-01-01",
		//EndTm:    "2022-01-02",
		//Search:   "admin",
	}
	resp, err := ADACli.cli.ListThreatBlock(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
	for _, item := range resp.List {
		t.Logf("threat block info:%#v", item)
	}
}
