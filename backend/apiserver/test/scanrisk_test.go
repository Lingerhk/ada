package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"testing"
)

func TestScanRiskStats(t *testing.T) {
	req := v2.ScanRiskStatsReq{
		Domain: "all",
		Type:   "baseline", // leak｜baseline
	}
	resp, err := ADACli.cli.ScanRiskStats(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan stats item:%#v", item)
	}
}

func TestListBaseline(t *testing.T) {
	req := v2.ListBaselineReq{
		PageIdx:  1,
		PageSize: 10,
	}
	resp, err := ADACli.cli.ListBaseline(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan baseline item:%#v", item)
	}
}

func TestGetBaseline(t *testing.T) {
	req := v2.GetBaselineReq{
		ID: "663065208da088cf0e70f1be",
	}
	resp, err := ADACli.cli.GetBaseline(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
	for _, entry := range resp.Entries {
		t.Logf("entrie:%v", entry)
	}
}

func TestListLeak(t *testing.T) {
	req := v2.ListLeakReq{
		PageIdx:  1,
		PageSize: 10,
	}
	resp, err := ADACli.cli.ListLeak(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan leak item:%#v", item)
	}
}

func TestListWeakPwd(t *testing.T) {
	req := v2.ListWeakPwdReq{
		PageIdx:  1,
		PageSize: 10,
	}
	resp, err := ADACli.cli.ListWeakPwd(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan weakpwd item:%#v", item)
	}
}

func TestListScanTask(t *testing.T) {
	req := v2.ListScanTaskReq{
		PageIdx:  1,
		PageSize: 10,
		Cycle:    "all",
		Type:     "baseline",
		Status:   "all",
	}
	resp, err := ADACli.cli.ListScanTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan task item:%#v", item)
	}
}

func TestGetScanTask(t *testing.T) {
	req := v2.GetScanTaskReq{
		//ID: "662b9d8961f1b7721b0ad4e0", // leak
		ID:       "663065208da088cf0e70f147", // baseline
		PageIdx:  1,
		PageSize: 10,
	}
	resp, err := ADACli.cli.GetScanTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan task:%#v", item)
	}
}

func TestAddScanTask(t *testing.T) {
	req := v2.AddScanTaskReq{
		Type: "weakpwd",
		Plans: map[string]string{
			//"chinasix.com": "6425b14857e6c3ceef50e461", // baseline
			//"chinasix.com": "6425b14857e6c3ceef50e462", // leak
			//"chinasix.com": "6425b14857e6c3ceef50e463", // weakpwd
			"china.com": "6425b14857e6c3ceef50e463", // weakpwd
		},
	}
	resp, err := ADACli.cli.AddScanTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestRecheckScanTask(t *testing.T) {
	req := v2.RecheckScanTaskReq{
		ID:   "662b9d8961f1b7721b0ad4f1",
		Type: "leak",
	}
	resp, err := ADACli.cli.RecheckScanTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestDeleteScanTask(t *testing.T) {
	req := v2.DeleteScanTaskReq{
		ID: "664607973f5d1fcb6ca29b1a",
	}
	resp, err := ADACli.cli.DeleteScanTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestListScanConf(t *testing.T) {
	req := v2.ListScanConfReq{
		PageIdx:  1,
		PageSize: 10,
	}
	resp, err := ADACli.cli.ListScanConf(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan conf item:%#v", item)
	}
}

func TestSetScanConf(t *testing.T) {
	req := v2.SetScanConfReq{
		ID:        "61094609ecdcfd018b66a58d",
		IsEnable:  true,
		CycleType: 2,
	}
	resp, err := ADACli.cli.SetScanConf(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)
}

func TestGetScanConf(t *testing.T) {
	req := v2.GetScanConfReq{
		ID: "61094609ecdcfd018b66a58b",
	}
	resp, err := ADACli.cli.GetScanConf(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp.Detail)
}

func TestUpdateScanConf(t *testing.T) {
	req := v2.UpdateScanConfReq{
		ID: "61094609ecdcfd018b66a58b",
		Plans: map[string]string{
			"china.com": "6425b14857e6c3ceef50e461",
		},
	}
	resp, err := ADACli.cli.UpdateScanConf(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)
}

func TestGetScanTmplNames(t *testing.T) {
	req := v2.GetScanTmplNamesReq{
		Type: "leak",
	}
	resp, err := ADACli.cli.GetScanTmplNames(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("get scan tmpl names:%#v", resp)
	for _, item := range resp.List {
		t.Logf("scan tmpl item:%#v", item)
	}
}

func TestListScanTmpl(t *testing.T) {
	req := v2.ListScanTmplReq{
		PageIdx:  1,
		PageSize: 10,
		Type:     "all",
	}
	resp, err := ADACli.cli.ListScanTmpl(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("scan tmpl item:%#v", item)
	}
}

func TestGetScanTmpl(t *testing.T) {
	req := v2.GetScanTmplReq{
		ID: "6425b14857e6c3ceef50e462",
	}
	resp, err := ADACli.cli.GetScanTmpl(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("get scan tmpl:%#v", resp)
	for _, item := range resp.Plugins {
		t.Logf("scan tmpl plugin item:%#v", item)
	}
}

func TestDeleteScanTmpl(t *testing.T) {
	req := v2.DeleteScanTmplReq{
		ID: "",
	}
	resp, err := ADACli.cli.DeleteScanTmpl(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("del scan tmpl:%#v", resp)
}

func TestAddScanTmpl(t *testing.T) {
	var plugins = []*v2.PluginInfoV2{}
	plugins = append(plugins, &v2.PluginInfoV2{
		ID:       101,
		Enable:   1,
		MetaData: map[string]string{"port": "446"},
	})

	plugins = append(plugins, &v2.PluginInfoV2{
		ID:       109,
		Enable:   1,
		MetaData: map[string]string{},
	})

	req := v2.AddScanTmplReq{
		Name:    "自定义漏洞扫描",
		Type:    "leak",
		Plugins: plugins,
	}
	resp, err := ADACli.cli.AddScanTmpl(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("add scan tmpl:%#v", resp)
}

func TestAddScanTmplV2(t *testing.T) {
	var plugins = []*v2.PluginInfoV2{}
	plugins = append(plugins, &v2.PluginInfoV2{
		ID:       10001,
		Enable:   1,
		MetaData: map[string]string{"password": "123\nadmin\n123456\npasswd\nroot"},
	})

	req := v2.AddScanTmplReq{
		Name:    "自定义弱口令扫描",
		Type:    "weakpwd",
		Plugins: plugins,
	}
	resp, err := ADACli.cli.AddScanTmpl(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("add scan tmpl:%#v", resp)
}

func TestUpdateScanTmpl(t *testing.T) {
	var plugins = []*v2.PluginInfoV2{}
	plugins = append(plugins, &v2.PluginInfoV2{
		ID:       101,
		Enable:   1,
		MetaData: map[string]string{"port": "446"},
	})
	plugins = append(plugins, &v2.PluginInfoV2{
		ID:       109,
		Enable:   0,
		MetaData: map[string]string{},
	})

	req := v2.UpdateScanTmplReq{
		ID:      "661f7e79c55cc36efab7a2f8",
		Name:    "自定义漏洞扫描rename",
		Plugins: plugins,
	}
	resp, err := ADACli.cli.UpdateScanTmpl(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("update scan tmpl:%#v", resp)
}

func TestListScanPlugin(t *testing.T) {
	req := v2.ListScanPluginReq{
		Type: "baseline",
	}
	resp, err := ADACli.cli.ListScanPlugin(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.Plugins {
		t.Logf("scan plugin item:%#v", item)
	}
}
