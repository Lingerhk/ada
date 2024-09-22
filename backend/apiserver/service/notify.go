package service

import (
	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/server"
	"ada/infra/base"
	"ada/infra/email"
	"bytes"
	"context"
	"fmt"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"log/syslog"
	"net"
	"net/http"
	"strings"
	"time"
)

func (s *ADAServiceV2) ListNotify(ctx context.Context, in *v2.ListNotifyReq) (*v2.ListNotifyReply, error) {
	ret := &v2.ListNotifyReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 0},
		Exhausted: true,
	}

	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	notifyList, total, err := server.FindAllNotify(s.env, in.MsgType, in.Status, in.StartTm, in.EndTm, in.OrderCreateTm, limit, offset)
	if err != nil {
		logger.Errorf("find notify failed,err:%v", err)
		return ret, status.Errorf(codes.Internal, "获取消息列表失败")
	}

	for _, n := range notifyList {
		ret.List = append(ret.List, &v2.ListNotifyReply_Details{
			ID:       n.ID.Hex(),
			Title:    n.Title,
			MsgType:  n.MsgType,
			Status:   n.Status,
			Params:   n.Params,
			CreateTm: n.CreateTm.String(),
		})
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	}
	return ret, nil
}

func (s *ADAServiceV2) UpdateNotify(ctx context.Context, in *v2.UpdateNotifyReq) (*v2.UpdateNotifyReply, error) {
	ret := v2.UpdateNotifyReply{Result: RESP_FAILED}

	err := server.UpdateNotifyStatus(s.env, in.IDs)
	if err != nil {
		logger.Errorf("update notify status err:%v", err)
		return &ret, status.Errorf(codes.Internal, "更新消息状态失败")
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) StatsNotify(ctx context.Context, in *v2.StatsNotifyReq) (*v2.StatsNotifyReply, error) {

	return nil, nil
}

func (s *ADAServiceV2) ListNotifyConf(ctx context.Context, in *v2.ListNotifyConfReq) (*v2.ListNotifyConfReply, error) {
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)

	notifyConfList, count, err := server.FindAllNotifyConf(s.env, in.ModuleName, in.NotifyType, in.Endpoint, in.Enable, in.SortTime, limit, offset)
	if err != nil {
		logger.Errorf("find notify email conf failed,err:%v", err)
		return nil, status.Errorf(codes.Internal, "获取告警配置列表失败")
	}

	var ret v2.ListNotifyConfReply
	for _, nc := range notifyConfList {
		ret.List = append(ret.List, &v2.ListNotifyConfReply_Details{
			Id:         nc.ID.Hex(),
			ModuleName: nc.ModuleName,
			NotifyType: nc.NotifyType,
			Endpoint:   nc.Endpoint,
			Remark:     nc.Remark,
			Enable:     nc.Enable,
			Metadata:   nc.MetaData,
			UpdateTm:   nc.UpdateTm.String(),
		})
	}

	ret.Page = &v2.ModelPage{
		PageIdx:  in.PageIdx,
		PageSize: in.PageSize,
		Total:    int32(count),
	}
	return &ret, nil
}

func (s *ADAServiceV2) UpdateNotifyConf(ctx context.Context, in *v2.UpdateNotifyConfReq) (*v2.UpdateNotifyConfReply, error) {
	ret := v2.UpdateNotifyConfReply{
		Result: RESP_FAILED,
	}

	nc, err := server.GetNotifyConf(s.env, in.Id)
	if err != nil {
		logger.Errorf("get notigy conf by id fail. error: %s", err)
		return &ret, status.Errorf(codes.Internal, "未能找到该通知模版")
	}

	if !checkNotifyMetadata(nc.NotifyType, in.Metadata) {
		return &ret, status.Errorf(codes.Internal, "通知信息Metadata不合法")
	}

	nc.Enable = in.Enable
	nc.Endpoint = in.Endpoint
	nc.MetaData = in.Metadata
	nc.UpdateTm = time.Now()

	err = server.UpdateNotifyConf(s.env, nc)
	if err != nil {
		logger.Errorf("UpdateNotifyConf err:%v", err)
		return &ret, status.Errorf(codes.Internal, "更新告警通知失败")
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) EnableNotifyConf(ctx context.Context, in *v2.EnableNotifyConfReq) (*v2.EnableNotifyConfReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Errorf(codes.Internal, "没有操作权限")
	}

	ret := v2.EnableNotifyConfReply{Result: RESP_FAILED}

	nc, err := server.GetNotifyConf(s.env, in.Id)
	if err != nil {
		logger.Errorf("get notigy conf by id fail. error: %s", err)
		return &ret, status.Errorf(codes.Internal, "未能找到告警配置信息")
	}

	nc.Enable = in.Enable
	err = server.UpdateNotifyConf(s.env, nc)
	if err != nil {
		logger.Errorf("update user err:%v", err)
		return &ret, status.Errorf(codes.Internal, "更新用户信息失败")
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) TestNotifyConf(ctx context.Context, in *v2.TestNotifyConfReq) (*v2.TestNotifyConfReply, error) {
	ret := v2.TestNotifyConfReply{Result: RESP_FAILED}
	testMessage := "ADA-System notify test message"

	switch in.NotifyType {
	case "syslog":
		// endpoint: udp://192.168.1.2:514
		parts := strings.SplitN(in.Endpoint, ":", 2)
		if len(parts) != 2 {
			logger.Errorf("invalid endpoint:%s", in.Endpoint)
			return &ret, nil
		}
		if parts[0] != "tcp" && parts[0] != "udp" {
			logger.Errorf("invalid proto(%s) in endpoint:%s", parts[0], in.Endpoint)
			return &ret, nil
		}
		if !strings.HasPrefix(parts[1], "//") {
			logger.Errorf("invalid address(%s) in endpoint:%s", parts[1], in.Endpoint)
			return &ret, nil
		}
		w, err := syslog.Dial(parts[0], parts[1][2:], syslog.LOG_ALERT, "ADA-System")
		if err != nil {
			logger.Errorf("init syslog client err:%v", err)
			return &ret, nil
		}
		if err := w.Alert(testMessage); err != nil {
			logger.Errorf("send syslog message err:%v", err)
			return &ret, nil
		}
	case "email":
		host, ok := in.Metadata["server"]
		if !ok {
			return &ret, status.Error(codes.Internal, "未传入服务器地址")
		}
		port, ok := in.Metadata["port"]
		if !ok {
			return &ret, status.Error(codes.Internal, "未传入服务器端口")
		}
		address := fmt.Sprintf("%s:%s", host, port)
		_, err := net.DialTimeout("tcp", address, time.Second*20)
		if err != nil {
			logger.Errorf("network connect %s err:%v", address, err)
			return &ret, nil
		}

		err = email.SendEmailV2(in.Metadata, "ADA-System", "<html><body><h3>"+testMessage+"/<h3></body></html>")
		if err != nil {
			logger.Infof("test send alarm email failed: %v", err)
			logger.Debugf("eq %t?", strings.ContainsAny(err.Error(), "too many message send today"))
			if err.Error() == "550 too many message send today." {
				ret.Msg = fmt.Sprintf("（%s邮箱）每日接收邮件数量达到上限", in.Metadata["username"])
				return &ret, nil
			}
			ret.Msg = err.Error()
			return &ret, nil
		}
	case "webhook":
		client := base.NewHTTPClient(10)

		data := []byte(fmt.Sprintf(`"title":"ADA-System","type":"webhook","message":"%s"}`, testMessage))
		req, err := http.NewRequest("GET", in.Endpoint, bytes.NewReader(data))
		if err != nil {
			return &ret, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			logger.Errorf("do request(%s) err:%v", in.Endpoint, err)
			return &ret, nil
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			logger.Errorf("send webhook request(%s) done, but response code:%d", in.Endpoint, resp.StatusCode)
			ret.Msg = fmt.Sprintf("请求已发送，但是响应Code异常：%d", resp.StatusCode)
			return &ret, nil
		}
	}

	ret.Result = RESP_SUCCESS
	ret.Msg = "发送成功"
	return &ret, nil
}

func checkNotifyMetadata(notifyType string, metadata map[string]string) bool {
	if _, ok := metadata["alert_interval"]; !ok {
		logger.Debugf("checkNotifyMetadata: alert_interval not found in metadata")
		return false
	}

	switch notifyType {
	case "email":
		for _, item := range []string{"server", "port", "username", "password", "receiver"} {
			if _, ok := metadata[item]; !ok {
				logger.Debugf("checkNotifyMetadata: %s not found in metadata", item)
				return false
			}
		}
	case "webhook":
		if _, ok := metadata["application_type"]; !ok {
			logger.Errorf("checkNotifyMetadata: application_type not found in metadata")
			return false
		}
	case "syslog":
		// do nothing
	default:
		logger.Errorf("invalid notify type:%s", notifyType)
		return false
	}

	return true
}
