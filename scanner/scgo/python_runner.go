package scgo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
)

const pyRunner = `
import os, sys, json, base64, importlib, traceback, datetime

# JSON encoder compatible with old scanner JsonEncoder
try:
    from datetime import datetime as datetime_type
    from datetime import date
except Exception:
    datetime_type = None
    date = None

class JsonEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            import bson
            if isinstance(obj, bson.objectid.ObjectId):
                return str(obj)
        except Exception:
            pass

        if datetime_type is not None and isinstance(obj, datetime_type):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        if date is not None and isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        return str(obj)

sc_root = os.environ.get('SC_ROOT')
if not sc_root:
    print('__ERROR__missing SC_ROOT')
    sys.exit(2)

sys.path.insert(0, sc_root)
os.chdir(sc_root)

module = os.environ.get('PLUGIN_MODULE')
if not module:
    print('__ERROR__missing PLUGIN_MODULE')
    sys.exit(2)

action = os.environ.get('PLUGIN_ACTION', 'verify')

kwargs_b64 = os.environ.get('PLUGIN_KWARGS_B64', '')
try:
    kwargs = json.loads(base64.b64decode(kwargs_b64).decode('utf-8')) if kwargs_b64 else {}
except Exception as e:
    print('__ERROR__bad kwargs: %s' % e)
    sys.exit(2)

# Provide a minimal celery current_task for plugins expecting it.
task_id = os.environ.get('TASK_ID', '')
try:
    import celery
    class DummyReq(dict):
        def __getattr__(self, name):
            return self.get(name)
    dummy = type("DummyTask", (), {})()
    dummy.request = DummyReq(id=task_id)
    try:
        import celery._state as _state
        _state._tls.current_task = dummy
    except Exception:
        pass
    try:
        celery.current_task = dummy
    except Exception:
        pass
except Exception:
    pass

try:
    m = importlib.import_module(module)
    Plugin = getattr(m, 'Plugin')
    if action == 'get_info':
        pkg = os.environ.get('PLUGIN_INFO_PATH')
        if not pkg:
            print('__ERROR__missing PLUGIN_INFO_PATH')
            sys.exit(2)
        res = Plugin.get_info(pkg)
    else:
        ins = Plugin(**kwargs)
        res = ins.verify()
    print('__RESULT__' + json.dumps(res, ensure_ascii=False, cls=JsonEncoder))
except Exception as e:
    print('__ERROR__' + str(e))
    traceback.print_exc(file=sys.stderr)
    sys.exit(2)
`

// RunPluginVerify imports plugin module (CPython .so) and runs Plugin.verify().
// It returns the parsed JSON result (dict) and raw stdout/stderr for troubleshooting.
func RunPluginVerify(pythonBin, scRoot, module string, kwargs map[string]any) (map[string]any, string, string, error) {
	pluginKwargs := kwargs
	taskID := ""
	if tid, ok := kwargs["_task_id"]; ok {
		taskID = fmt.Sprintf("%v", tid)
		pluginKwargs = make(map[string]any, len(kwargs)-1)
		for k, v := range kwargs {
			if k == "_task_id" {
				continue
			}
			pluginKwargs[k] = v
		}
	}

	b, err := json.Marshal(pluginKwargs)
	if err != nil {
		return nil, "", "", err
	}
	kwargsB64 := base64.StdEncoding.EncodeToString(b)

	cmd := exec.Command(pythonBin, "-c", pyRunner)
	cmd.Dir = scRoot
	cmd.Env = pluginPythonEnv(cmd.Environ(), scRoot,
		"SC_ROOT="+scRoot,
		"PLUGIN_MODULE="+module,
		"PLUGIN_ACTION=verify",
		"PLUGIN_KWARGS_B64="+kwargsB64,
	)
	if taskID != "" {
		cmd.Env = append(cmd.Env, "TASK_ID="+taskID)
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err = cmd.Run()
	dur := time.Since(start)

	outStr := stdout.String()
	errStr := stderr.String()
	if dur > 30*time.Second {
		logger.Warnf("plugin verify slow module=%s dur=%s", module, dur)
	}

	// Parse marker line.
	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "__RESULT__") {
			payload := strings.TrimPrefix(line, "__RESULT__")
			var res map[string]any
			if e := json.Unmarshal([]byte(payload), &res); e != nil {
				return nil, outStr, errStr, fmt.Errorf("decode plugin result: %w", e)
			}
			return res, outStr, errStr, nil
		}
		if strings.HasPrefix(line, "__ERROR__") {
			msg := strings.TrimPrefix(line, "__ERROR__")
			if err == nil {
				err = fmt.Errorf("plugin error: %s", msg)
			}
		}
	}

	if err == nil {
		err = ErrPluginResultNotFound
	}
	return nil, outStr, errStr, err
}

func pluginPythonEnv(base []string, scRoot string, extra ...string) []string {
	return append(setEnv(base, "PYTHONPATH", pluginPythonPath(scRoot)), extra...)
}

func pluginPythonPath(scRoot string) string {
	paths := []string{scRoot}
	venvRoot := filepath.Join(filepath.Dir(scRoot), ".venv", "lib")
	matches, _ := filepath.Glob(filepath.Join(venvRoot, "python*", "site-packages"))
	sort.Strings(matches)
	for _, p := range matches {
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			paths = append(paths, p)
		}
	}
	if existing := os.Getenv("PYTHONPATH"); existing != "" {
		paths = append(paths, existing)
	}
	return strings.Join(paths, string(os.PathListSeparator))
}

func setEnv(base []string, key, value string) []string {
	prefix := key + "="
	out := make([]string, 0, len(base)+1)
	for _, item := range base {
		if strings.HasPrefix(item, prefix) {
			continue
		}
		out = append(out, item)
	}
	return append(out, prefix+value)
}
