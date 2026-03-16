package server

import (
	"ada/backend/tasker/api"
	"ada/backend/tasker/tasks"
	"context"
	"encoding/json"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (ts *TaskServer) GetTaskState(ctx context.Context, in *api.GetTaskStateReq) (*api.GetTaskStateReply, error) {
	logger.Infof("get task state task of %+v", in)
	//get backend
	backend := ts.taskSrv.GetBackend()

	taskState, err := backend.GetState(in.TaskUUID)
	if err != nil {
		logger.Infof("get task state err:%v", err)
		return nil, status.Error(codes.Internal, "获取任务状态失败")
	}

	ret := &api.GetTaskStateReply{
		TaskUUID:  taskState.TaskUUID,
		TaskName:  taskState.TaskName,
		State:     taskState.State,
		Error:     taskState.Error,
		CreatedAt: taskState.CreatedAt.String(),
	}
	return ret, nil
}

func (ts *TaskServer) DomainStatusSyncTask(ctx context.Context, in *api.DomainStatusSyncTaskReq) (*api.DomainStatusSyncTaskReply, error) {
	asyncResult, err := ts.taskSrv.SendTaskWithContext(ctx, tasks.TaskDomainSync())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	taskState := asyncResult.GetState()
	return &api.DomainStatusSyncTaskReply{TaskID: taskState.TaskUUID}, nil
}

func (ts *TaskServer) DomainLdapSyncTask(ctx context.Context, in *api.DomainLdapSyncTaskReq) (*api.DomainLdapSyncTaskReply, error) {
	asyncResult, err := ts.taskSrv.SendTaskWithContext(ctx, tasks.TaskADLdapSync())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	taskState := asyncResult.GetState()
	return &api.DomainLdapSyncTaskReply{TaskID: taskState.TaskUUID}, nil
}

func (ts *TaskServer) ScannerBaselineTask(ctx context.Context, in *api.ScannerBaselineTaskReq) (*api.ScannerBaselineTaskReply, error) {
	dtm, _ := json.Marshal(in.DomainTmplMap)
	asyncResult, err := ts.taskSrv.SendTaskWithContext(ctx, tasks.TaskScannerBaseline(string(dtm)))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	taskState := asyncResult.GetState()
	return &api.ScannerBaselineTaskReply{TaskID: taskState.TaskUUID}, nil
}

func (ts *TaskServer) ScannerLeakTask(ctx context.Context, in *api.ScannerLeakTaskReq) (*api.ScannerLeakTaskReply, error) {
	dtm, _ := json.Marshal(in.DomainTmplMap)
	asyncResult, err := ts.taskSrv.SendTaskWithContext(ctx, tasks.TaskScannerLeak(string(dtm)))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	taskState := asyncResult.GetState()
	return &api.ScannerLeakTaskReply{TaskID: taskState.TaskUUID}, nil
}

func (ts *TaskServer) ScannerWeakPwdTask(ctx context.Context, in *api.ScannerWeakPwdTaskReq) (*api.ScannerWeakPwdTaskReply, error) {
	dtm, _ := json.Marshal(in.DomainTmplMap)
	asyncResult, err := ts.taskSrv.SendTaskWithContext(ctx, tasks.TaskScannerWeakPwd(string(dtm)))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	taskState := asyncResult.GetState()
	return &api.ScannerWeakPwdTaskReply{TaskID: taskState.TaskUUID}, nil
}

func (ts *TaskServer) ScannerRecheckTask(ctx context.Context, in *api.ScannerRecheckTaskReq) (*api.ScannerRecheckTaskReply, error) {
	asyncResult, err := ts.taskSrv.SendTaskWithContext(ctx, tasks.TaskScannerRecheck(in.ScanType, in.SubTaskId))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	taskState := asyncResult.GetState()
	return &api.ScannerRecheckTaskReply{TaskID: taskState.TaskUUID}, nil
}

func (ts *TaskServer) ExportReportTask(ctx context.Context, in *api.ExportReportTaskReq) (*api.ExportReportTaskReply, error) {
	asyncResult, err := ts.taskSrv.SendTaskWithContext(ctx, tasks.TaskExportReport(in.TaskID, in.Type, in.Params))
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	taskState := asyncResult.GetState()
	return &api.ExportReportTaskReply{TaskID: taskState.TaskUUID}, nil
}

// Cron wrapper methods (no gRPC context required)

func (ts *TaskServer) CronScannerBaselineTask(plans map[string]string) error {
	dtm, _ := json.Marshal(plans)
	_, err := ts.taskSrv.SendTask(tasks.TaskScannerBaseline(string(dtm)))
	if err != nil {
		logger.Errorf("CronScannerBaselineTask error: %v", err)
		return err
	}
	return nil
}

func (ts *TaskServer) CronScannerLeakTask(plans map[string]string) error {
	dtm, _ := json.Marshal(plans)
	_, err := ts.taskSrv.SendTask(tasks.TaskScannerLeak(string(dtm)))
	if err != nil {
		logger.Errorf("CronScannerLeakTask error: %v", err)
		return err
	}
	return nil
}

func (ts *TaskServer) CronScannerWeakPwdTask(plans map[string]string) error {
	dtm, _ := json.Marshal(plans)
	_, err := ts.taskSrv.SendTask(tasks.TaskScannerWeakPwd(string(dtm)))
	if err != nil {
		logger.Errorf("CronScannerWeakPwdTask error: %v", err)
		return err
	}
	return nil
}
