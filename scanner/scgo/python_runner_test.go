package scgo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPluginPythonEnvIncludesVenvSitePackages(t *testing.T) {
	runPath := t.TempDir()
	scRoot := filepath.Join(runPath, ".sc")
	sitePackages := filepath.Join(runPath, ".venv", "lib", "python3.7", "site-packages")
	if err := os.MkdirAll(scRoot, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sitePackages, 0755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("PYTHONPATH", "/already/set")

	env := pluginPythonEnv([]string{"PYTHONPATH=/old", "KEEP=1"}, scRoot, "EXTRA=2")
	got := ""
	for _, item := range env {
		if strings.HasPrefix(item, "PYTHONPATH=") {
			got = strings.TrimPrefix(item, "PYTHONPATH=")
		}
	}
	if got == "" {
		t.Fatal("PYTHONPATH not set")
	}

	parts := strings.Split(got, string(os.PathListSeparator))
	want := []string{scRoot, sitePackages, "/already/set"}
	if len(parts) != len(want) {
		t.Fatalf("PYTHONPATH parts = %v, want %v", parts, want)
	}
	for i := range want {
		if parts[i] != want[i] {
			t.Fatalf("PYTHONPATH parts = %v, want %v", parts, want)
		}
	}
	if strings.Contains(got, "/old") {
		t.Fatalf("old PYTHONPATH leaked into %q", got)
	}
}

func TestPluginRunnerGetInfoIntegration(t *testing.T) {
	pythonBin := os.Getenv("SCGO_TEST_PYTHON")
	scRoot := os.Getenv("SCGO_TEST_SC_ROOT")
	module := os.Getenv("SCGO_TEST_MODULE")
	pkgPath := os.Getenv("SCGO_TEST_PKG")
	if pythonBin == "" || scRoot == "" || module == "" || pkgPath == "" {
		t.Skip("set SCGO_TEST_PYTHON, SCGO_TEST_SC_ROOT, SCGO_TEST_MODULE, and SCGO_TEST_PKG to run")
	}

	res, out, errStr, err := RunPluginGetInfo(pythonBin, scRoot, module, pkgPath)
	if err != nil {
		t.Fatalf("RunPluginGetInfo err=%v\nstdout=%s\nstderr=%s", err, out, errStr)
	}
	if len(res) == 0 {
		t.Fatal("RunPluginGetInfo returned empty result")
	}
}
