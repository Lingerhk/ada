package service

import (
	"ada/backend/apiserver/api/rpc"
	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/config"
	"ada/backend/apiserver/server"
	baseCommon "ada/backend/common"
	"ada/backend/model"
	"ada/infra/base"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type weakPwdUserList []struct {
	Name         string `json:"name"`
	SamName      string `json:"sam_account_name"`
	Password     string `json:"password"`
	LastUpdateTm string `json:"password_last_update_tm"`
	ExpirationTm string `json:"expiration_tm"`
	UpdateTm     string `json:"update_tm"`
	Locked       int32  `json:"is_lock"`
}

func (s *ADAServiceV2) ScanRiskStats(ctx context.Context, in *v2.ScanRiskStatsReq) (*v2.ScanRiskStatsReply, error) {
	var domains []string
	if in.Domain == "all" {
		domainList, err := server.GetDomainList(s.env)
		if err != nil {
			logger.Errorf("get domain list err:%v", err)
			return nil, status.Error(codes.Internal, s.I18n("InternalError"))
		}
		for _, dm := range domainList {
			if dm.Status == baseCommon.DomainStatusInit {
				continue
			}
			domains = append(domains, dm.Name)
		}
	} else {
		domains = []string{in.Domain}
	}

	var ret v2.ScanRiskStatsReply
	var countMap = make(map[string]map[string]int32)
	for _, dName := range domains {
		subTasks, err := server.GetLatestSubTaskByDomain(s.env, dName, in.Type)
		if err != nil {
			logger.Warnf("get latest scan task by domain err:%v", err)
			return nil, status.Error(codes.Internal, s.I18n("InternalError"))
		}
		if subTasks == nil || len(subTasks) == 0 {
			continue
		}

		for _, st := range subTasks {
			typ := st.Result.Plugin.Type
			hasRisk := false
			if st.Result.Status > 0 {
				hasRisk = true
			}

			stats, ok := countMap[typ]
			if ok {
				if hasRisk {
					stats["risk"] += 1
				} else {
					stats["normal"] += 1
				}
			} else {
				countMap[typ] = make(map[string]int32)
				countMap[typ]["normal"] = 1
				countMap[typ]["risk"] = 0
			}
		}
	}

	for typ, stats := range countMap {
		desc, ok := baseCommon.ScanTypeDescMap[typ]
		if ok {
			ret.List = append(ret.List, &v2.ScanRiskStatsReply_Details{
				SubType:     typ,
				SubTypeDesc: desc,
				RiskTotal:   stats["risk"],
				NormalTotal: stats["normal"],
			})
		}
	}

	return &ret, nil
}

func (s *ADAServiceV2) ListBaseline(ctx context.Context, in *v2.ListBaselineReq) (*v2.ListBaselineReply, error) {
	ret := &v2.ListBaselineReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 0},
		Exhausted: true,
	}

	// 先从tb_scan_tasks表获取最新一次leak类型的记录_id
	baseline, err := server.GetLatestTaskByType(s.env, "baseline")
	if err != nil {
		logger.Errorf("get latest baseline err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("ScanRisk.ListBaseline.GetBaselineFailed"))
	}
	if baseline == nil {
		ret.List = nil
		return ret, nil
	}

	// 再从tb_scan_subtasks表按group_id过滤结果
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	subTasks, total, err := server.FindBaselineListSelect(s.env, baseline.ID.Hex(), in.Domain, in.SubType, in.Level, in.Result, in.Search, in.OrderUpdateTm, limit, offset)
	if err != nil {
		logger.Errorf("find baseline list err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("ScanRisk.ListBaseline.GetBaselineListFailed"))
	}

	var instanceList []map[string]interface{}

	for _, t := range subTasks {
		byteData, _ := json.Marshal(t.Result.Data["instance_list"])
		err = json.Unmarshal(byteData, &instanceList)
		if err != nil {
			logger.Errorf("json unmarshal reuslt.data.instance_list err:%v", err)
			return ret, status.Error(codes.Internal, s.I18n("ScanRisk.DataParseError"))
		}

		ret.List = append(ret.List, &v2.ListBaselineReply_Details{
			ID:       t.ID.Hex(),
			Name:     t.Result.Plugin.Name,
			Domain:   t.Params["domain"].(string),
			SubType:  t.Result.Plugin.Type,
			Level:    t.Result.Plugin.RiskLevel,
			Result:   t.Result.Status,
			Entries:  int32(len(instanceList)),
			UpdateTm: t.UpdateTm.String(),
		})
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	}
	return ret, nil
}

func (s *ADAServiceV2) GetBaseline(ctx context.Context, in *v2.GetBaselineReq) (*v2.GetBaselineReply, error) {
	subTask, err := server.GetScanSubTaskById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get baseline err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.GetBaseline.GetBaselineFailed"))
	}

	var instanceList []map[string]interface{}
	byteData, _ := json.Marshal(subTask.Result.Data["instance_list"])
	err = json.Unmarshal(byteData, &instanceList)
	if err != nil {
		logger.Errorf("json unmarshal reuslt.data.instance_list err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.DataParseError"))
	}

	var entries []*v2.GetBaselineReplyEntryInfo
	for _, ins := range instanceList {
		entries = append(entries, &v2.GetBaselineReplyEntryInfo{
			Info: getPluginMetadata(ins),
		})
	}

	ret := v2.GetBaselineReply{
		ID:         subTask.ID.Hex(),
		Name:       subTask.Result.Plugin.Name,
		Domain:     subTask.Params["domain"].(string),
		SubType:    subTask.Result.Plugin.Type,
		Level:      subTask.Result.Plugin.RiskLevel,
		Result:     subTask.Result.Status,
		Entries:    entries,
		Desc:       subTask.Result.Plugin.Desc,
		VerifyDesc: subTask.Result.Plugin.VerifyDesc,
		Suggestion: subTask.Result.Plugin.Suggestion,
		Reference:  subTask.Result.Plugin.Reference,
		UpdateTm:   subTask.UpdateTm.String(),
	}

	return &ret, nil
}

func (s *ADAServiceV2) ListLeak(ctx context.Context, in *v2.ListLeakReq) (*v2.ListLeakReply, error) {
	ret := &v2.ListLeakReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 0},
		Exhausted: true,
	}

	// 先从tb_scan_tasks表获取最新一次leak类型的记录_id
	leak, err := server.GetLatestTaskByType(s.env, "leak")
	if err != nil {
		logger.Errorf("get latest leak err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("ScanRisk.ListLeak.GetLeakFailed"))
	}
	if leak == nil {
		ret.List = nil
		return ret, nil
	}

	// 再从tb_scan_subtasks表按group_id过滤结果
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	subTasks, total, err := server.FindLeakListSelect(s.env, leak.ID.Hex(), in.Domain, in.SubType, in.Level, in.Result, in.Search, in.StartTm, in.EndTm, in.OrderUpdateTm, limit, offset)
	if err != nil {
		logger.Errorf("find leak list err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("ScanRisk.ListLeak.GetLeakListFailed"))
	}

	for _, t := range subTasks {
		ret.List = append(ret.List, &v2.ListLeakReply_Details{
			ID:         t.ID.Hex(),
			Name:       t.Result.Plugin.Name,
			Domain:     t.Params["domain"].(string),
			DcHostname: fmt.Sprintf("%s.%s", t.Params["hostname"].(string), t.Params["domain"].(string)),
			SubType:    t.Result.Plugin.Type,
			Level:      t.Result.Plugin.RiskLevel,
			Result:     t.Result.Status,
			Suggestion: t.Result.Plugin.Suggestion,
			Reference:  t.Result.Plugin.Reference,
			CreateTm:   t.CreateTm.String(),
			UpdateTm:   t.UpdateTm.String(),
		})
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	}
	return ret, nil
}

func (s *ADAServiceV2) ListWeakPwd(ctx context.Context, in *v2.ListWeakPwdReq) (*v2.ListWeakPwdReply, error) {
	ret := &v2.ListWeakPwdReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 0},
		Exhausted: true,
	}

	// 先从tb_scan_tasks表获取最新一次leak类型的记录_id
	weakPwd, err := server.GetLatestTaskByType(s.env, "weakpwd")
	if err != nil {
		logger.Errorf("get latest weakpwd err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("ScanRisk.ListWeakPwd.GetWeakPwdFailed"))
	}
	if weakPwd == nil {
		ret.List = nil
		return ret, nil
	}

	// 再从tb_scan_subtasks表按group_id过滤结果
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	subTasks, total, err := server.FindWeakPwdListSelect(s.env, weakPwd.ID.Hex(), in.Domain, limit, offset)
	if err != nil {
		logger.Errorf("find weakpwd list err:%v", err)
		return ret, status.Error(codes.Internal, s.I18n("ScanRisk.ListWeakPwd.GetWeakPwdListFailed"))
	}

	// debug
	logger.Infof("weakPwd:%s, subTasks len:%d", weakPwd.ID.Hex(), len(subTasks))

	var idx int32
	var userList weakPwdUserList
	for _, taskCnt := range subTasks {
		domain := taskCnt.Result.Data["domain"].(string)
		byteData, _ := json.Marshal(taskCnt.Result.Data["users"])
		err = json.Unmarshal(byteData, &userList)
		if err != nil {
			logger.Errorf("json unmarshal reuslt.data.users err:%v", err)
			return ret, status.Error(codes.Internal, s.I18n("ScanRisk.DataParseError"))
		}

		if len(in.Domain) > 0 {
			if !base.InArray(domain, in.Domain) {
				continue
			}
		}

		for _, user := range userList {
			if len(in.Locked) > 0 {
				if !base.InArray(user.Locked, in.Locked) {
					continue
				}
			}
			var searchContain = false
			if in.Search != "" {
				if strings.Contains(user.SamName, in.Search) || strings.Contains(user.Name, in.Search) {
					searchContain = true
				}
				if !searchContain {
					continue
				}
			}

			password := "****"
			if in.IsPlain {
				password = user.Password
			}

			idx += 1
			ret.List = append(ret.List, &v2.ListWeakPwdReply_Details{
				ID:           idx,
				Username:     user.Name,
				SamName:      user.SamName,
				Password:     password,
				ExpirationTm: user.ExpirationTm,
				LastUpdateTm: user.LastUpdateTm,
				Domain:       domain,
				Locked:       user.Locked,
				UpdateTm:     user.UpdateTm,
			})

			logger.Infof("subtask_id:%s, sam_name:%s, domain:%s\n", taskCnt.ID.Hex(), user.SamName, domain)
		}
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	}

	return ret, nil
}

func (s *ADAServiceV2) ListScanTask(ctx context.Context, in *v2.ListScanTaskReq) (*v2.ListScanTaskReply, error) {
	ret := &v2.ListScanTaskReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 0},
		Exhausted: true,
	}

	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	taskList, total, err := server.FindScanTasksSelect(s.env, in.Type, in.Status, in.Cycle, in.StartTm, in.EndTm, in.OrderCreateTm, in.OrderUpdateTm, limit, offset)
	if err != nil {
		logger.Errorf("find alert activity by event id :%v", err)
		return ret, status.Error(codes.Internal, s.I18n("ScanRisk.GetScanTaskListFailed"))
	}

	for _, t := range taskList {
		ret.List = append(ret.List, &v2.ListScanTaskReply_Details{
			ID:             t.ID.Hex(),
			Type:           t.Type,
			Cycle:          t.Trigger,
			Status:         t.Status,
			SubTasks:       t.SubTasksTotal,
			SubtasksFinish: t.SubTasksFin,
			ErrorMsg:       t.ErrMsg,
			CreateTm:       t.CreateTm.String(),
			UpdateTm:       t.UpdateTm.String(),
		})
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	}

	return ret, nil
}

func (s *ADAServiceV2) GetScanTask(ctx context.Context, in *v2.GetScanTaskReq) (*v2.GetScanTaskReply, error) {
	task, err := server.GetScanTasksById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get scan task by id(%s) err:%v", in.ID, err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.GetScanTaskFailed"))
	}

	ret := &v2.GetScanTaskReply{
		Page:      &v2.ModelPage{PageSize: in.PageSize, PageIdx: in.PageIdx, Total: 0},
		Exhausted: true,
	}

	ret.HeadType = task.Type
	// 通过task.Type 定义header
	if task.Type == "baseline" {
		ret.HeadField = []string{"ID", "基线名称", "所在域", "基线类型", "风险等级", "影响对象数量", "检测结果", "最后检测时间"}
	} else if task.Type == "leak" {
		ret.HeadField = []string{"ID", "漏洞名称", "所在域", "域控制器", "漏洞类型", "风险等级", "检测结果", "最后检测时间"}
	} else if task.Type == "weakpwd" {
		ret.HeadField = []string{"ID", "用户名", "SAM名称", "密码", "过期时间", "密码修改时间", "用户状态", "所在域", "模版名称", "最后检测时间"}
	}

	// 再从tb_scan_subtasks表按group_id过滤结果
	var limit, offset = in.PageSize, in.PageSize * (in.PageIdx - 1)
	subTasks, total, err := server.FindSubScanTasks(s.env, task.ID.Hex(), limit, offset)
	if err != nil {
		logger.Errorf("find sub tasks list err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.GetScanTaskListFailed"))
	}

	for _, t := range subTasks {
		if t.Status != "FINISH" {
			continue
		}

		tmpl, err := server.GetScanTmplById(s.env, t.Params["template_id"].(string))
		if err != nil {
			logger.Errorf("get scan tmpl by id(%s) err:%v", t.Params["template_id"].(string), err)
			continue
		}

		// 根据 task.Type 类型处理params
		params := make(map[string]string)
		if task.Type == "baseline" || task.Type == "leak" {
			if task.Type == "baseline" {
				if t.Result.Status == 0 {
					params["entries"] = "0"
				} else {
					var instanceList []map[string]interface{}
					byteData, _ := json.Marshal(t.Result.Data["instance_list"])
					err = json.Unmarshal(byteData, &instanceList)
					if err != nil {
						logger.Errorf("json unmarshal reuslt.data.instance_list err:%v", err)
						continue
					}
					params["entries"] = fmt.Sprintf("%d", len(instanceList))
				}
			}

			var dcHostname string
			if task.Type == "leak" {
				dcHostname = fmt.Sprintf("%s.%s", t.Params["hostname"].(string), t.Params["domain"].(string))
			}

			ret.List = append(ret.List, &v2.GetScanTaskReply_Details{
				ID:         t.ID.Hex(),
				Name:       t.Result.Plugin.Name,
				Domain:     t.Params["domain"].(string),
				DcHostname: dcHostname,
				TmplName:   tmpl.Name,
				SubType:    t.Result.Plugin.Type,
				Level:      t.Result.Plugin.RiskLevel,
				Result:     t.Result.Status,
				Params:     params,
				UpdateTm:   t.UpdateTm.String(),
			})
		} else if task.Type == "weakpwd" {
			var userList weakPwdUserList
			byteData, _ := json.Marshal(t.Result.Data["users"])
			err = json.Unmarshal(byteData, &userList)
			if err != nil {
				logger.Errorf("json unmarshal reuslt.data.users err:%v", err)
				continue
			}

			for _, user := range userList {
				total += 1
				params["username"] = user.Name
				params["sam_name"] = user.SamName
				params["password"] = "****"
				params["expiration_tm"] = user.ExpirationTm
				params["last_update_tm"] = user.LastUpdateTm
				params["locked"] = fmt.Sprintf("%d", user.Locked)

				ret.List = append(ret.List, &v2.GetScanTaskReply_Details{
					ID:       t.ID.Hex(),
					Name:     t.Result.Plugin.Name,
					Domain:   t.Params["domain"].(string),
					TmplName: tmpl.Name,
					SubType:  t.Result.Plugin.Type,
					Level:    t.Result.Plugin.RiskLevel,
					Result:   t.Result.Status,
					Params:   params,
					UpdateTm: t.UpdateTm.String(),
				})
			}
		}
	}

	ret.Page.Total = int32(total)
	if (limit + offset) < int32(total) {
		ret.Exhausted = false
	}

	return ret, nil
}

func (s *ADAServiceV2) AddScanTask(ctx context.Context, in *v2.AddScanTaskReq) (*v2.AddScanTaskReply, error) {
	ret := v2.AddScanTaskReply{Result: RESP_FAILED}

	var plans = make(map[string]string)
	for domain, tmplId := range in.Plans {
		dm, _ := server.GetDomainByName(s.env, domain)
		if dm == nil {
			logger.Errorf("get domain(name:%s) by name failed", domain)
			return &ret, status.Error(codes.InvalidArgument, s.I18n("InvalidArgument"))
		}

		// check scan tmpl exist by id
		tmplIns, _ := server.GetScanTmplById(s.env, tmplId)
		if tmplIns == nil {
			logger.Warnf("get scan tmpl(id:%s) by id faild", tmplId)
			return &ret, status.Error(codes.InvalidArgument, s.I18n("InvalidArgument"))
		}
		if tmplIns.Type != in.Type {
			logger.Warnf("get scan tmpl(id:%s) faild, it's type is:%s", tmplId, tmplIns.Type)
			return &ret, status.Error(codes.InvalidArgument, s.I18n("InvalidArgument"))
		}

		plans[domain] = tmplId
	}

	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err != nil {
		logger.Errorf("new rpc client err:%v", err)
	} else {
		defer client.Close()

		var taskId string
		switch in.Type {
		case "baseline":
			taskId, err = client.ScannerBaselineTask(plans)
		case "leak":
			taskId, err = client.ScannerLeakTask(plans)
		case "weakpwd":
			taskId, err = client.ScannerWeakPwdTask(plans)
		}
		if err != nil {
			logger.Errorf("send scanner task(type:%s) err:%v", in.Type, err)
			return &ret, err
		}
		logger.Infof("send scanner task(type:%s) succeed, task_id:%s", in.Type, taskId)
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) RecheckScanTask(ctx context.Context, in *v2.RecheckScanTaskReq) (*v2.RecheckScanTaskReply, error) {
	ret := v2.RecheckScanTaskReply{Result: RESP_FAILED}

	client, err := rpc.NewClient(ctx, s.env.Cfg.BindSrv.TaskAddr)
	if err != nil {
		logger.Errorf("new rpc client err:%v", err)
	} else {
		defer client.Close()
		taskId, err := client.ScannerRecheckTask(in.Type, in.ID)
		if err != nil {
			logger.Errorf("send scanner recheck task(type:%s, subtask_id:%s) err:%v", in.Type, in.ID, err)
			return &ret, err
		}
		logger.Infof("send scanner recheck task(type:%s) succeed, task_id:%s", in.Type, taskId)
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) DeleteScanTask(ctx context.Context, in *v2.DeleteScanTaskReq) (*v2.DeleteScanTaskReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	ret := v2.DeleteScanTaskReply{Result: RESP_FAILED}

	task, err := server.GetScanTasksById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get scan task by id(%s) err:%v", in.ID, err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.GetScanTaskFailed"))
	}

	// 如果是weakpwd类型的，需要删除tb_domain_xxx_hash表
	if task.Type == "weakpwd" {
		tb := fmt.Sprintf("tb_domain_%s_hash", task.Domain)
		if err := server.DropDomainUserHash(s.env, tb); err != nil {
			logger.Warnf("drop domain user hash table err:%v", err)
		}
	}

	err = server.DeleteScanTasks(s.env, in.ID)
	if err != nil {
		logger.Errorf("get scan task by id(%s) err:%v", in.ID, err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.GetScanTaskFailed"))
	}

	ret.Result = RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) ListScanConf(ctx context.Context, in *v2.ListScanConfReq) (*v2.ListScanConfReply, error) {
	cnfList, err := server.FindAllScanConf(s.env)
	if err != nil {
		logger.Errorf("get scan conf err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanConf.GetScanConfFailed"))
	}

	var ret v2.ListScanConfReply
	for _, cnf := range cnfList {
		ret.List = append(ret.List, &v2.ScanConfDetail{
			ID:        cnf.ID.Hex(),
			Name:      cnf.Name,
			Type:      cnf.Type,
			IsEnable:  cnf.IsEnable,
			CycleType: cnf.CycleType,
			Rate:      cnf.Rate,
			Desc:      cnf.Desc,
			Plans:     cnf.Plans,
			CreateTm:  cnf.CreateTm.String(),
			UpdateTm:  cnf.UpdateTm.String(),
		})
	}

	ret.Exhausted = true
	ret.Page = &v2.ModelPage{
		PageIdx:  in.PageIdx,
		PageSize: in.PageSize,
		Total:    int32(len(cnfList)),
	}

	return &ret, nil
}

func (s *ADAServiceV2) SetScanConf(ctx context.Context, in *v2.SetScanConfReq) (*v2.SetScanConfReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	ret := v2.SetScanConfReply{Result: RESP_FAILED}

	updater := bson.M{"is_enable": in.IsEnable, "cycle_type": in.CycleType, "rate": in.Rate, "update_tm": time.Now()}
	err := server.UpdateScanConf(s.env, in.ID, updater)
	if err != nil {
		logger.Errorf("update scan conf err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanConf.UpdateFailed"))
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) GetScanConf(ctx context.Context, in *v2.GetScanConfReq) (*v2.GetScanConfReply, error) {
	cnf, err := server.GetScanConfById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get scan conf(id:%s) err:%v", in.ID, err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanConf.GetScanConfFailed"))
	}

	ret := v2.GetScanConfReply{
		Detail: &v2.ScanConfDetail{
			ID:        cnf.ID.Hex(),
			Name:      cnf.Name,
			Type:      cnf.Type,
			IsEnable:  cnf.IsEnable,
			CycleType: cnf.CycleType,
			Rate:      cnf.Rate,
			Desc:      cnf.Desc,
			Plans:     cnf.Plans,
			CreateTm:  cnf.CreateTm.String(),
			UpdateTm:  cnf.UpdateTm.String(),
		},
	}

	return &ret, nil
}

func (s *ADAServiceV2) UpdateScanConf(ctx context.Context, in *v2.UpdateScanConfReq) (*v2.UpdateScanConfReply, error) {
	if !s.IsSuper(ctx) {
		return nil, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	ret := v2.UpdateScanConfReply{Result: RESP_FAILED}

	_, err := server.GetScanConfById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get scan conf(id:%s) err:%v", in.ID, err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanConf.GetScanConfFailed"))
	}

	var plans = make(map[string]string)
	for domain, tmplId := range in.Plans {
		dm, _ := server.GetDomainByName(s.env, domain)
		if dm == nil {
			logger.Warnf("get domain(name:%s) by name faild, will ignore!", domain)
			continue
		}

		// check scan tmpl exist by id
		tmplIns, _ := server.GetScanTmplById(s.env, tmplId)
		if tmplIns == nil {
			logger.Warnf("get scan tmpl(id:%s) by id faild, will ignore!", tmplId)
			continue
		}
		plans[domain] = tmplId
	}

	if len(plans) == 0 {
		return &ret, status.Error(codes.InvalidArgument, s.I18n("InvalidArgument"))
	}

	updater := bson.M{"plans": plans, "update_tm": time.Now()}
	err = server.UpdateScanConf(s.env, in.ID, updater)
	if err != nil {
		logger.Errorf("update scan conf err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanConf.UpdateFailed"))
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) GetScanTmplNames(ctx context.Context, in *v2.GetScanTmplNamesReq) (*v2.GetScanTmplNamesReply, error) {
	tmplList, err := server.FindScanTmplSelect(s.env, in.Type, 100, 0)
	if err != nil {
		logger.Errorf("list scan tmpl err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.GetScanTmplNamesFailed"))
	}

	var ret v2.GetScanTmplNamesReply
	for _, tmpl := range tmplList {
		ret.List = append(ret.List, &v2.GetScanTmplNamesReplyTmplNames{ID: tmpl.ID.Hex(), Name: tmpl.Name})
	}

	return &ret, nil
}

func (s *ADAServiceV2) ListScanTmpl(ctx context.Context, in *v2.ListScanTmplReq) (*v2.ListScanTmplReply, error) {
	limit, offset := in.PageSize, (in.PageIdx-1)*in.PageSize
	tmplList, err := server.FindScanTmplSelect(s.env, in.Type, int64(limit), int64(offset))
	if err != nil {
		logger.Errorf("list scan tmpl err:%v", err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.GetScanTmplFailed"))
	}

	var ret v2.ListScanTmplReply
	for _, tmpl := range tmplList {
		ret.List = append(ret.List, &v2.ListScanTmplReply_Details{
			ID:       tmpl.ID.Hex(),
			Name:     tmpl.Name,
			Type:     tmpl.Type,
			TmplType: tmpl.TmplType,
			UpdateTm: tmpl.UpdateTm.String(),
		})
	}

	ret.Exhausted = true
	ret.Page = &v2.ModelPage{
		PageIdx:  in.PageIdx,
		PageSize: in.PageSize,
		Total:    int32(len(tmplList)),
	}

	return &ret, nil
}

func (s *ADAServiceV2) GetScanTmpl(ctx context.Context, in *v2.GetScanTmplReq) (*v2.GetScanTmplReply, error) {
	tmpl, err := server.GetScanTmplById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get scan tmpl by id(%s) err:%v", in.ID, err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.GetScanTmplFailed"))
	}

	var plugins []*v2.PluginInfo
	for _, p := range tmpl.Plugins {
		plugins = append(plugins, &v2.PluginInfo{
			ID:       p.ID,
			Name:     p.Name,
			Type:     p.Type,
			Level:    p.Level,
			Enable:   p.Enable,
			MetaData: getPluginMetadata(p.MetaData),
		})
	}

	ret := v2.GetScanTmplReply{
		ID:       tmpl.ID.Hex(),
		Name:     tmpl.Name,
		Type:     tmpl.Type,
		Plugins:  plugins,
		TmplType: tmpl.TmplType,
		CreateTm: tmpl.CreateTm.String(),
		UpdateTm: tmpl.CreateTm.String(),
	}

	return &ret, nil
}

func (s *ADAServiceV2) UpdateScanTmpl(ctx context.Context, in *v2.UpdateScanTmplReq) (*v2.UpdateScanTmplReply, error) {
	ret := v2.UpdateScanTmplReply{Result: RESP_FAILED}

	if !s.IsSuper(ctx) {
		return &ret, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	tmpl, err := server.GetScanTmplById(s.env, in.ID)
	if err != nil {
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.GetScanTmplFailed"))
	}

	plugins, err := getPluginList(s.env, tmpl.Type, in.Plugins)
	if err != nil {
		logger.Errorf("get plugin list err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.UpdateFailed"))
	}

	err = server.UpdateScanTmpl(s.env, in.ID, in.Name, plugins)
	if err != nil {
		logger.Errorf("update scan tmpl err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.UpdateFailed"))
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) DeleteScanTmpl(ctx context.Context, in *v2.DeleteScanTmplReq) (*v2.DeleteScanTmplReply, error) {
	ret := v2.DeleteScanTmplReply{Result: RESP_FAILED}

	if !s.IsSuper(ctx) {
		return &ret, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	tmpl, err := server.GetScanTmplById(s.env, in.ID)
	if err != nil {
		logger.Errorf("get scan tmpl by id(%s) err:%v", in.ID, err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.GetScanTmplFailed"))
	}

	if tmpl.TmplType == 1 {
		return &ret, status.Error(codes.Canceled, s.I18n("ScanRisk.ScanTmpl.DefaultTmplNotDelete"))
	}

	// TODO: delete the scan tmpl related domain in scan conf.

	err = server.DeleteScanTmpl(s.env, in.ID)
	if err != nil {
		logger.Errorf("delete scan tmpl err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.DeleteFailed"))
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) AddScanTmpl(ctx context.Context, in *v2.AddScanTmplReq) (*v2.AddScanTmplReply, error) {
	ret := v2.AddScanTmplReply{Result: RESP_FAILED}

	if !s.IsSuper(ctx) {
		return &ret, status.Error(codes.PermissionDenied, s.I18n("NoPermission"))
	}

	tmpl, _ := server.GetScanTmplByName(s.env, in.Name)
	if tmpl != nil {
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.NameExists"))
	}

	plugins, err := getPluginList(s.env, in.Type, in.Plugins)
	if err != nil {
		logger.Errorf("get plugin list err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.AddFailed"))
	}

	err = server.AddScanTmpl(s.env, in.Name, in.Type, plugins)
	if err != nil {
		logger.Errorf("add scan tmpl err:%v", err)
		return &ret, status.Error(codes.Internal, s.I18n("ScanRisk.ScanTmpl.AddFailed"))
	}

	ret.Result = common.RESP_SUCCESS
	return &ret, nil
}

func (s *ADAServiceV2) ListScanPlugin(ctx context.Context, in *v2.ListScanPluginReq) (*v2.ListScanPluginReply, error) {
	plugins, err := server.FindScanPluginSelect(s.env, in.Type)
	if err != nil {
		logger.Errorf("get scan plugins by type(%s) err:%v", in.Type, err)
		return nil, status.Error(codes.Internal, s.I18n("ScanRisk.ScanPlugin.GetScanPluginFailed"))
	}

	ret := v2.ListScanPluginReply{}
	for _, p := range plugins {
		ret.Plugins = append(ret.Plugins, &v2.PluginInfo{
			ID:       p.ID,
			Name:     p.Name,
			Type:     p.Type,
			Level:    p.Level,
			Enable:   p.Enable,
			MetaData: getPluginMetadata(p.MetaData),
		})
	}

	return &ret, nil
}

// getPluginMetadata 处理medata map[string]interface{}， 只有weakPassword类型的password: []string
func getPluginMetadata(md map[string]interface{}) map[string]string {
	var metadata = make(map[string]string)
	for k, v := range md {
		switch v.(type) {
		case bool:
			metadata[k] = fmt.Sprintf("%t", v)
		case string:
			metadata[k] = fmt.Sprintf("%s", v)
		case int32, int64, int:
			metadata[k] = fmt.Sprintf("%d", v)
		case float64, float32:
			metadata[k] = fmt.Sprintf("%f", v)
		case []string:
			metadata[k] = strings.Join(v.([]string), "\n")
		case primitive.A:
			var parts []string
			for _, item := range []interface{}(v.(primitive.A)) {
				parts = append(parts, item.(string))
			}
			metadata[k] = strings.Join(parts, "\n")
		default:
			metadata[k] = "unknown type"
		}
	}

	return metadata
}

// getPluginList 根据id list，获取完整的plugins
func getPluginList(env *config.Env, typ string, pluginInfo []*v2.PluginInfoV2) ([]model.ScanPlugin, error) {
	var plugins []model.ScanPlugin

	for _, pi := range pluginInfo {
		plug, err := server.GetScanPluginById(env, pi.ID)
		if err != nil {
			logger.Warnf("plugin(id:%d) does not exsit, err:%v, will ignore!", pi.ID, err)
			continue
		}

		plug.Enable = pi.Enable
		if typ == "weakpwd" {
			// metadata特殊处理
			if v, ok := pi.MetaData["password"]; ok {
				passwords := strings.Split(v, "\n")
				plug.MetaData["password"] = passwords
			}
		} else {
			for k, v := range pi.MetaData {
				plug.MetaData[k] = v
			}
		}

		plugins = append(plugins, plug)
	}

	return plugins, nil
}
