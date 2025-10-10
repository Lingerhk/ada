package service

import (
	"ada/backend/apiserver/api/rpc"
	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/server"
	baseCommon "ada/backend/common"
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/uuid"
	logger "github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *ADAServiceV2) ListExportTask(ctx context.Context, in *v2.ListExportTaskReq) (*v2.ListExportTaskReply, error) {
	limit, offset := in.PageSize, (in.PageIdx-1)*in.PageSize
	tasks, total, err := server.FindExportTask(s.env, in.Type, in.Status, in.StartTm, in.EndTm, in.SortTime, limit, offset)
	if err != nil {
		logger.Errorf("find export task err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("QueryFailed"))
	}

	var ret v2.ListExportTaskReply
	for _, task := range tasks {
		ret.List = append(ret.List, &v2.ListExportTaskReply_Details{
			ID:       task.ID.Hex(),
			Name:     task.Name,
			Type:     task.Type,
			Params:   task.Params,
			FileType: task.FileType,
			Status:   task.Status,
			CreateTm: task.CreateTm.String(),
			UpdateTm: task.UpdateTm.String(),
			FilePath: task.FilePath,
			ErrMsg:   task.ErrMsg,
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

func (s *ADAServiceV2) AddExportTask(ctx context.Context, in *v2.AddExportTaskReq) (*v2.AddExportTaskReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	ret := v2.AddExportTaskReply{Result: RESP_FAILED}

	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err != nil {
		logger.Errorf("new rpc client err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("RpcClientFailed"))
	}
	defer client.Close()

	taskId := fmt.Sprintf("task_%v", uuid.New().String()) // 生成任务ID,并写入db

	_, err = client.ExportReportTask(taskId, in.Type, in.Params)
	if err != nil {
		logger.Warnf("send domain status sync task err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("RpcTaskFailed"))
	}

	// 向ExportTask表中插入一条记录
	err = server.AddExportTask(s.env, in.Name, in.Type, taskId, in.Params)
	if err != nil {
		logger.Errorf("add export report task err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("Report.AddExportTask.AddFailed"))
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) DeleteExportTask(ctx context.Context, in *v2.DeleteExportTaskReq) (*v2.DeleteExportTaskReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	ret := v2.DeleteExportTaskReply{Result: RESP_FAILED}

	tk, err := server.DeleteExportTaskByID(s.env, in.ID)
	if err != nil {
		logger.Errorf("find export task err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("Report.DeleteExportTask.DeleteFailed"))
	}

	if tk.Status == "finish" {
		taskFile := filepath.Join(baseCommon.ROOT_PATH, "download", "report", fmt.Sprintf("%s.%s", tk.FilePath, tk.FileType))
		if err := os.Remove(taskFile); err != nil {
			logger.Warnf("try to delete task file(%s) err:%v, will ignore!", taskFile, err)
		}
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}
