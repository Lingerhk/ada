package scgo

import (
	"ada/infra/gocelery"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type BaselineTask struct {
	svc    *Service
	kwargs map[string]any
	id     string
}

func (t *BaselineTask) WithContext(ctx context.Context) gocelery.CeleryTask {
	if t == nil {
		return nil
	}

	clone := *t
	clone.svc = t.svc.WithContext(ctx)
	return &clone
}

func (t *BaselineTask) ParseKwargs(kwargs map[string]any) error {
	t.kwargs = kwargs
	t.id = asString(kwargs["_task_id"])
	if t.id == "" {
		// fallback
		t.id = asString(kwargs["task_id"])
	}
	return nil
}

func (t *BaselineTask) RunTask() (any, error) {
	groupID := asString(t.kwargs["group_id"])
	domainName := asString(t.kwargs["domain"])
	templateID := asString(t.kwargs["template_id"])
	retryID := asString(t.kwargs["retry_id"])
	pluginID, _ := asInt32(t.kwargs["plugin_id"])

	now := nowUTC()

	// step 1 update task/subtask status
	if retryID == "" {
		_ = t.svc.updateScanTaskByIDHex(groupID, bson.M{"$set": bson.M{"status": "RUNNING", "update_tm": now}})
	} else {
		// baseline retry only updates subtask update_tm
		t.id = retryID
		_ = t.svc.updateSubTaskByTaskID(t.id, bson.M{"$set": bson.M{"update_tm": now}})
	}

	plugin, err := t.svc.getTemplatePlugin(templateID, pluginID)
	if err != nil {
		return nil, err
	}

	// step 2 execute plugin
	res, pluginErr := t.execPluginBaseline(domainName, plugin)
	pluginResult := res
	if pluginErr != nil {
		pluginResult = map[string]any{"status": int32(-1), "error": pluginErr.Error(), "plugin": plugin}
	}
	pluginResult["plugin"] = plugin

	// step 3 update subtask
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

	// step 4 update scan task progress
	if retryID == "" {
		upd := bson.M{"$inc": bson.M{"subtasks_finish": 1}, "$set": bson.M{"update_tm": nowUTC()}}
		if errMsg != "" {
			upd["$set"].(bson.M)["error_msg"] = errMsg
		}
		_ = t.svc.updateScanTaskByIDHex(groupID, upd)
	} else {
		// only update update_tm
		upd := bson.M{"$set": bson.M{"update_tm": nowUTC()}}
		if errMsg != "" {
			upd["$set"].(bson.M)["error_msg"] = errMsg
		}
		_ = t.svc.updateScanTaskByIDHex(groupID, upd)
	}

	// push notify
	if st == 1 {
		title, _ := plugin["display"].(string)
		desc, _ := plugin["desc"].(string)
		pid := fmt.Sprintf("%v", plugin["_id"])
		level := fmt.Sprintf("%v", plugin["risk_level"])
		typ := fmt.Sprintf("%v", plugin["type"])
		subType := fmt.Sprintf("%v", plugin["sub_type"])
		params := map[string]string{"task_id": t.id, "level": level, "rule_id": pid, "sub_type": subType}
		notify := map[string]any{"title": title, "desc": desc, "msg_type": "baseline", "event_type": typ, "params": params, "timestamp": time.Now().Unix()}
		pushNotify(t.svc.RedisCli, notify)
	}

	// step 5 finalize task status when all done
	taskDoc, err := t.svc.getScanTaskByIDHex(groupID)
	if err == nil {
		total, _ := asInt32(taskDoc["subtasks_total"])
		fin, _ := asInt32(taskDoc["subtasks_finish"])
		if total > 0 && fin >= total {
			if retryID != "" {
				return pluginResult, nil
			}
			finishCount, _ := t.svc.countSubTasks(groupID, "FINISH")
			final := "FAILURE"
			if finishCount > 0 {
				final = "FINISH"
			}
			_ = t.svc.updateScanTaskByIDHex(groupID, bson.M{"$set": bson.M{"status": final, "update_tm": nowUTC()}})
		}
	}

	// return a json string for compatibility with celery result backend consumers
	b, _ := json.Marshal(pluginResult)
	return string(b), nil
}

func (t *BaselineTask) execPluginBaseline(domainName string, plugin map[string]any) (map[string]any, error) {
	dm, err := t.svc.getDomainByName(domainName)
	if err != nil {
		return nil, err
	}
	dc, ok := getOnlineDC(dm)
	if !ok {
		return nil, fmt.Errorf("no online dc for domain %s", domainName)
	}

	ldapConf, _ := mapFromAny(dm["ldap_conf"])
	meta, _ := mapFromAny(plugin["meta_data"])
	mongoEnv, err := MongoEnvFromConfig(t.svc.Cfg)
	if err != nil {
		return nil, err
	}

	dcConf := map[string]any{
		"ldap_conf": ldapConf,
		"name":      dm["name"],
		"ip":        firstIP(dc),
		"hostname":  dm["dc_hostname"],
		"fqdn":      "",
		"platform":  "",
	}
	if ldapConf != nil {
		if srv, ok := ldapConf["server"].(string); ok {
			parts := strings.Split(srv, "//")
			if len(parts) == 2 {
				dcConf["fqdn"] = parts[1]
			}
		}
	}
	if p, ok := dc["platform"].(string); ok {
		dcConf["platform"] = p
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
		// fallback by category
		cat, _ := plugin["category"].(string)
		module = fmt.Sprintf("plugins.%s.plugin_%d.main", cat, pid)
	}

	res, out, errStr, e := RunPluginVerify(t.svc.PythonBin, t.svc.ScRoot, module, kwargs)
	if e != nil {
		logPluginError(module, out, errStr, e)
		return nil, e
	}

	// baseline truncation
	if data, ok := res["data"].(map[string]any); ok {
		if inst, ok := data["instance_list"].([]any); ok {
			if len(inst) > 10000 {
				data["instance_list"] = inst[:10000]
			}
		}
	}

	return res, nil
}

func pluginIDFrom(plugin map[string]any) int32 {
	id, _ := asInt32(plugin["_id"])
	return id
}
