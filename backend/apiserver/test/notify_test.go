package test

import (
	v2 "ada/backend/apiserver/api/v2"
	logger "github.com/sirupsen/logrus"
	"testing"
)

func TestListNotifyConf(t *testing.T) {
	req := v2.ListNotifyConfReq{
		PageIdx:  1,
		PageSize: 10,
	}

	resp, err := ADACli.cli.ListNotifyConf(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	logger.Infof("%+v", resp)
}

func TestUpdateNotifyConf(t *testing.T) {
	req := v2.UpdateNotifyConfReq{
		Id:       "6602db662a7f7b96c1f67c55",
		Enable:   "enable",
		Endpoint: "https://open.feishu.cn/open-apis/bot/v2/hook/6cd351a0-343b-4c9f-bee7-63324d9d392a",
		Level:    []int32{2, 3, 4, 5},
		Metadata: map[string]string{
			"alert_interval":   "20",
			"application_type": "feishu",
		},
	}

	resp, err := ADACli.cli.UpdateNotifyConf(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}
	logger.Infof("%+v", resp)
}
