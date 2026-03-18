package scgo

import (
	"ada/infra/gocelery"
	"context"
	"encoding/json"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type WeakPwdTask struct {
	svc    *Service
	kwargs map[string]any
	id     string
}

func (t *WeakPwdTask) WithContext(ctx context.Context) gocelery.CeleryTask {
	if t == nil {
		return nil
	}

	clone := *t
	clone.svc = t.svc.WithContext(ctx)
	return &clone
}

func (t *WeakPwdTask) ParseKwargs(kwargs map[string]any) error {
	t.kwargs = kwargs
	t.id = asString(kwargs["_task_id"])
	if t.id == "" {
		t.id = asString(kwargs["task_id"])
	}
	return nil
}

func (t *WeakPwdTask) RunTask() (any, error) {
	groupID := asString(t.kwargs["group_id"])
	domainName := asString(t.kwargs["domain"])
	templateID := asString(t.kwargs["template_id"])
	retryID := asString(t.kwargs["retry_id"])
	pluginID, _ := asInt32(t.kwargs["plugin_id"])

	now := nowUTC()

	// step1
	if retryID != "" {
		t.id = retryID
		_ = t.svc.updateSubTaskByTaskID(t.id, bson.M{"$set": bson.M{"status": "RUNNING", "params": t.kwargs, "result": bson.M{}, "update_tm": now}})
	} else {
		_ = t.svc.updateScanTaskByIDHex(groupID, bson.M{"$set": bson.M{"status": "RUNNING", "update_tm": now}})
	}

	plugin, err := t.svc.getTemplatePlugin(templateID, pluginID)
	if err != nil {
		return nil, err
	}

	res, pluginErr := t.execPluginWeakPwd(domainName, plugin)
	pluginResult := res
	if pluginErr != nil {
		pluginResult = map[string]any{"status": int32(-1), "error": pluginErr.Error(), "plugin": plugin}
	}
	pluginResult["plugin"] = plugin

	status := "FINISH"
	errMsg := ""
	st, _ := asInt32(pluginResult["status"])
	if st == -1 {
		status = "FAILURE"
		if s, ok := pluginResult["error"].(string); ok {
			errMsg = s
		}
	}

	_ = t.svc.updateSubTaskByTaskID(t.id, bson.M{"$set": bson.M{"status": status, "result": pluginResult, "error_msg": errMsg, "update_tm": nowUTC()}})

	// weakpwd subtasks_finish increments by user_list size (stored in mongo subtask params)
	subDoc, err := t.svc.getSubTaskByTaskID(t.id)
	incN := int32(1)
	if err == nil {
		paramsAny := subDoc["params"]
		params, ok := paramsAny.(map[string]any)
		if !ok {
			if bm, ok2 := paramsAny.(bson.M); ok2 {
				params = map[string]any(bm)
			}
		}
		if params != nil {
			if ul, ok := params["user_list"].([]any); ok {
				if len(ul) == 0 {
					if c, ok2 := asInt32(params["count"]); ok2 {
						incN = c
					} else {
						incN = 0
					}
				} else {
					incN = int32(len(ul))
				}
			}
		}
	}

	if retryID == "" {
		upd := bson.M{"$inc": bson.M{"subtasks_finish": incN}, "$set": bson.M{"update_tm": nowUTC()}}
		if errMsg != "" {
			upd["$set"].(bson.M)["error_msg"] = errMsg
		}
		_ = t.svc.updateScanTaskByIDHex(groupID, upd)
	} else {
		upd := bson.M{"$set": bson.M{"update_tm": nowUTC()}}
		if errMsg != "" {
			upd["$set"].(bson.M)["error_msg"] = errMsg
		}
		_ = t.svc.updateScanTaskByIDHex(groupID, upd)
	}

	// finalize
	taskDoc, err := t.svc.getScanTaskByIDHex(groupID)
	if err == nil {
		total, _ := asInt32(taskDoc["subtasks_total"])
		fin, _ := asInt32(taskDoc["subtasks_finish"])
		if total > 0 && fin >= total {
			if retryID != "" {
				return pluginResult, nil
			}
			final := "FINISH"
			if em, ok := taskDoc["error_msg"].(string); ok && em != "" {
				final = "FAILURE"
			}
			_ = t.svc.updateScanTaskByIDHex(groupID, bson.M{"$set": bson.M{"status": final, "update_tm": nowUTC()}})
		}
	}

	b, _ := json.Marshal(pluginResult)
	return string(b), nil
}

func (t *WeakPwdTask) execPluginWeakPwd(domainName string, plugin map[string]any) (map[string]any, error) {
	dm, err := t.svc.getDomainByName(domainName)
	if err != nil {
		return nil, err
	}
	dc, ok := getOnlineDCWeakPwd(dm)
	if !ok {
		return nil, fmt.Errorf("no available dc for weakpwd (port 445) domain=%s", domainName)
	}

	ldapConf, ok := mapFromAny(dm["ldap_conf"])
	if !ok {
		return nil, fmt.Errorf("invalid ldap_conf for domain %s", domainName)
	}

	mongoEnv, err := MongoEnvFromConfig(t.svc.Cfg)
	if err != nil {
		return nil, err
	}
	meta, _ := mapFromAny(plugin["meta_data"])

	dcConf := map[string]any{
		"ldap_conf": ldapConf,
		"name":      dm["name"],
		"ip":        firstIP(dc),
		"hostname":  dc["hostname"],
		"fqdn":      fmt.Sprintf("%v.%v", dc["hostname"], dm["name"]),
		"platform":  dc["platform"],
	}

	kwargs := map[string]any{
		"dc_conf":   dcConf,
		"meta_data": meta,
		"env": map[string]any{
			"mongo_conf": mongoEnv,
		},
	}
	kwargs["_task_id"] = t.id

	pid := pluginIDFrom(plugin)
	entry := t.svc.Plugins.ByID[pid]
	module := ""
	if entry != nil {
		module = entry.Module
	} else {
		cat, _ := plugin["category"].(string)
		module = fmt.Sprintf("plugins.%s.plugin_%d.main", cat, pid)
	}

	res, out, errStr, e := RunPluginVerify(t.svc.PythonBin, t.svc.ScRoot, module, kwargs)
	if e != nil {
		logPluginError(module, out, errStr, e)
		return nil, e
	}
	return res, nil
}
