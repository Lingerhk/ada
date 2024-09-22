package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"testing"
)

func TestListExportTask(t *testing.T) {
	req := v2.ListExportTaskReq{
		PageIdx:  1,
		PageSize: 10,
		Type:     []string{"all"},
		Status:   []string{"all"},
		//StartTm:  "2020-10-05 00:00:00",
		//EndTm:    "2020-10-06 00:00:00",
		SortTime: 1,
	}
	resp, err := ADACli.cli.ListExportTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)

	for _, item := range resp.List {
		t.Logf("ts:%v", item)
	}
}

func TestAddExportTask(t *testing.T) {
	req := v2.AddExportTaskReq{
		Name:   "告警事件测试",
		Type:   "alert_event",
		Params: map[string]string{"start_tm": "2020-10-05 00:00:00", "end_tm": "2024-10-05 00:00:00", "domain": "china.com", "level": "2,3,4,5"},
	}
	resp, err := ADACli.cli.AddExportTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)
}

func TestDeleteExportTask(t *testing.T) {
	req := v2.DeleteExportTaskReq{
		ID: "5f7b3b7b7b7b7b7b7b7b7b7b",
	}
	resp, err := ADACli.cli.DeleteExportTask(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	t.Logf("%#v", resp)
}
