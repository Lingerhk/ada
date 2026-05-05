package scgo

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// RunPluginGetInfo imports plugin module (.so) and calls Plugin.get_info(package.json).
func RunPluginGetInfo(pythonBin, scRoot, module, pkgPath string) (map[string]any, string, string, error) {
	cmd := exec.Command(pythonBin, "-c", pyRunner)
	cmd.Dir = scRoot
	cmd.Env = pluginPythonEnv(cmd.Environ(), scRoot,
		"SC_ROOT="+scRoot,
		"PLUGIN_MODULE="+module,
		"PLUGIN_ACTION=get_info",
		"PLUGIN_INFO_PATH="+pkgPath,
		"PLUGIN_KWARGS_B64="+base64.StdEncoding.EncodeToString([]byte("{}")),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	outStr := stdout.String()
	errStr := stderr.String()

	for _, line := range strings.Split(outStr, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "__RESULT__") {
			payload := strings.TrimPrefix(line, "__RESULT__")
			var res map[string]any
			if e := json.Unmarshal([]byte(payload), &res); e != nil {
				return nil, outStr, errStr, fmt.Errorf("decode plugin info: %w", e)
			}
			return res, outStr, errStr, nil
		}
	}

	if err == nil {
		err = ErrPluginResultNotFound
	}
	return nil, outStr, errStr, err
}
