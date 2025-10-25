package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"testing"
)

func TestSystemInfo(t *testing.T) {
	req := v2.GetSystemInfoReq{}
	resp, err := ADACli.cli.GetSystemInfo(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)
}

func TestSystemStats(t *testing.T) {
	req := v2.GetSystemStatsReq{
		Scope: "2h",
		Type:  "load",
	}

	resp, err := ADACli.cli.GetSystemStats(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, s := range resp.Stats {
		t.Logf("ts:%s, val:%s", s.Timestamp, s.Value)
	}
}

func TestNetworkDebug(t *testing.T) {
	req := v2.NetworkDebugReq{
		Type:   "nc",
		Target: "45.113.192.101:80",
	}

	resp, err := ADACli.cli.NetworkDebug(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("Result: %s", resp.Result)
}

func TestGetLicense(t *testing.T) {
	req := v2.GetLicenseReq{}
	resp, err := ADACli.cli.GetLicense(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("trait:%v", resp)
}

func TestUpdateLicense(t *testing.T) {
	// trait: d2535bd8f65378db8098a52fc6c2cd91
	// key1: LP+BAwEBB0xpY2Vuc2UB/4IAAQMBBERhdGEBCgABAVIB/4QAAQFTAf+EAAAACv+DBQEC/4YAAAD/wv+CAVd7InNuIjoiQURBIiwidHJhaXQiOiJkMjUzNWJkOGY2NTM3OGRiODA5OGE1MmZjNmMyY2Q5MSIsImNvdW50IjoxMDAsImVuZF90bSI6MTc0Mjk4MDE1OH0BMQKzUHISkTr8Bh4vOEyUrRz5/3vwLsTCzOiVutqH6e5IP9iI9gP4hfLwE41lcEWcacsBMQJML22sutFyz5yZcTb93ir1aP9oJYDA0pCq/ULggRFjiSg0rda5Xw//bSWVVKipFdcA
	// key2: LP+BAwEBB0xpY2Vuc2UB/4IAAQMBBERhdGEBCgABAVIB/4QAAQFTAf+EAAAACv+DBQEC/4YAAAD/wv+CAVd7InNuIjoiQURBIiwidHJhaXQiOiJkMjUzNWJkOGY2NTM3OGRiODA5OGE1MmZjNmMyY2Q5MSIsImNvdW50IjoxMDAsImVuZF90bSI6MTc1MTcyNjIzNX0BMQI/Jc77TOmfPGcDx2ggEVInO0uIuHcelldE360KbYT5Pc44TjHb6wujTPA0+hM9+QkBMQJwtha02PYH+gRrNyHWTKx0eYL9sPdnbkxg7nqQmnRdGhWaJ3C7y5wS51EFlVKL8kQA

	req := v2.UpdateLicenseReq{
		LicenseKey: "LP+BAwEBB0xpY2Vuc2UB/4IAAQMBBERhdGEBCgABAVIB/4QAAQFTAf+EAAAACv+DBQEC/4YAAAD/wv+CAVd7InNuIjoiQURBIiwidHJhaXQiOiJkMjUzNWJkOGY2NTM3OGRiODA5OGE1MmZjNmMyY2Q5MSIsImNvdW50IjoxMDAsImVuZF90bSI6MTc1MTcyNjIzNX0BMQI/Jc77TOmfPGcDx2ggEVInO0uIuHcelldE360KbYT5Pc44TjHb6wujTPA0+hM9+QkBMQJwtha02PYH+gRrNyHWTKx0eYL9sPdnbkxg7nqQmnRdGhWaJ3C7y5wS51EFlVKL8kQA",
	}

	resp, err := ADACli.cli.UpdateLicense(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("Result: %s", resp.Result)
}

func TestUpdateNtpAddress(t *testing.T) {
	// cn.pool.ntp.org
	// ntp.tencent.com

	req := v2.UpdateSystemCfgReq{Ntp: "ntp.tencent.com"}
	resp, err := ADACli.cli.UpdateSystemCfg(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)
}

func TestSetSystemStatsCfg(t *testing.T) {
	req := v2.SetSystemStatsCfgReq{
		Stats: map[string]string{"es_disk_percent_delete": "91"},
	}

	resp, err := ADACli.cli.SetSystemStatsCfg(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)
}
