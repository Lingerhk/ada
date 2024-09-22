package rpc

import (
	"ada/backend/tasker/api"
	"context"
	"encoding/json"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"time"
)

type AdaTaskCli struct {
	ctx    context.Context
	client api.ADATaskClient
	conn   *grpc.ClientConn
	cancel context.CancelFunc
}

// 实例化client
func NewClient(ctx context.Context, address string) (*AdaTaskCli, error) {
	conn, err := grpc.Dial(address, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		logger.Errorf("dial err: %v", err)
		_ = conn.Close()
		return nil, err
	}

	if ctx == nil {
		ctx = context.Background()
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	client := api.NewADATaskClient(conn)

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		cancel()
		return nil, status.Errorf(codes.InvalidArgument, "空数据")
	}

	ctx = metadata.NewOutgoingContext(context.Background(), md)
	return &AdaTaskCli{
		ctx:    ctx,
		client: client,
		conn:   conn,
		cancel: cancel,
	}, nil
}

// 调用完接口func后需要调用此接口： defer cli.Close()
func (tc *AdaTaskCli) Close() {
	tc.conn.Close()
	tc.cancel()
}

func (tc *AdaTaskCli) GetTaskState(taskUUID string) (*api.GetTaskStateReply, error) {
	taskReq := api.GetTaskStateReq{
		TaskUUID: taskUUID,
	}

	resp, err := tc.client.GetTaskState(tc.ctx, &taskReq)
	if err != nil {
		logger.Errorf("grpc call err: %v", err)
		return resp, err
	}
	return resp, nil
}

func (tc *AdaTaskCli) DomainStatusSyncTask() (string, error) {
	taskReq := api.DomainStatusSyncTaskReq{}

	resp, err := tc.client.DomainStatusSyncTask(tc.ctx, &taskReq)
	if err != nil {
		return "", err
	}
	logger.Infof("send domain_sync task(id: %s) success", resp.TaskID)

	return resp.TaskID, nil
}

func (tc *AdaTaskCli) DomainLdapSyncTask() (string, error) {
	taskReq := api.DomainLdapSyncTaskReq{}

	resp, err := tc.client.DomainLdapSyncTask(tc.ctx, &taskReq)
	if err != nil {
		return "", err
	}
	logger.Infof("send domain_ldap task(id: %s) success", resp.TaskID)

	return resp.TaskID, nil
}

func (tc *AdaTaskCli) ScannerBaselineTask(plans map[string]string) (string, error) {
	taskReq := api.ScannerBaselineTaskReq{
		DomainTmplMap: plans,
	}

	resp, err := tc.client.ScannerBaselineTask(tc.ctx, &taskReq)
	if err != nil {
		return "", err
	}
	logger.Infof("send baseline task(id: %s) success", resp.TaskID)

	return resp.TaskID, nil
}

func (tc *AdaTaskCli) ScannerLeakTask(plans map[string]string) (string, error) {
	taskReq := api.ScannerLeakTaskReq{
		DomainTmplMap: plans,
	}

	resp, err := tc.client.ScannerLeakTask(tc.ctx, &taskReq)
	if err != nil {
		return "", err
	}
	logger.Infof("send leak task(id: %s) success", resp.TaskID)

	return resp.TaskID, nil
}

func (tc *AdaTaskCli) ScannerWeakPwdTask(plans map[string]string) (string, error) {
	taskReq := api.ScannerWeakPwdTaskReq{
		DomainTmplMap: plans,
	}

	resp, err := tc.client.ScannerWeakPwdTask(tc.ctx, &taskReq)
	if err != nil {
		return "", err
	}
	logger.Infof("send weakpwd task(id: %s) success", resp.TaskID)

	return resp.TaskID, nil
}

func (tc *AdaTaskCli) ScannerRecheckTask(typ, subTaskId string) (string, error) {
	taskReq := api.ScannerRecheckTaskReq{
		ScanType:  typ,
		SubTaskId: subTaskId,
	}

	resp, err := tc.client.ScannerRecheckTask(tc.ctx, &taskReq)
	if err != nil {
		return "", err
	}
	logger.Infof("send recheck task(id: %s) success", resp.TaskID)

	return resp.TaskID, nil
}

func (tc *AdaTaskCli) ExportReportTask(taskId, typ string, params map[string]string) (string, error) {
	paramsStr, err := json.Marshal(params)
	if err != nil {
		return "", err
	}

	taskReq := api.ExportReportTaskReq{
		TaskID: taskId,
		Type:   typ,
		Params: string(paramsStr),
	}

	resp, err := tc.client.ExportReportTask(tc.ctx, &taskReq)
	if err != nil {
		return "", err
	}
	logger.Infof("send export_scan_risk task(id: %s) success", resp.TaskID)

	return resp.TaskID, nil
}
