package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"testing"
)

func TestListSensor(t *testing.T) {
	req := v2.ListSensorReq{
		PageIdx:  1,
		PageSize: 10,
	}
	resp, err := ADACli.cli.ListSensor(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	for _, item := range resp.List {
		t.Logf("sensor item:%#v", item)
	}
}

func TestUninstallSensor(t *testing.T) {
	req := v2.CmdSensorReq{
		Cmd: "uninstall",
		ID:  "a29a19b8-b403-46cf-b4ff-e728dce95b1b",
	}
	resp, err := ADACli.cli.CmdSensor(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("resp:%#v", resp)
}
