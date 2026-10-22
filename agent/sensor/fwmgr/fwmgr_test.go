package fwmgr

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystem is a scriptable System for driving Manager logic on any OS.
type fakeSystem struct {
	installed   bool
	svcExists   bool
	svcRunning  bool
	svcErr      error
	events      []int
	eventsErr   error
	eventCalls  int
	runErr      map[string]error // keyed by the single manager arg, e.g. "/start"
	runOut      map[string]string
	calls       []string
	runOverride func(arg string) error
}

func (f *fakeSystem) Exists(string) bool { return f.installed }

func (f *fakeSystem) RunManager(_ context.Context, exe string, args ...string) (string, error) {
	arg := strings.Join(args, " ")
	f.calls = append(f.calls, arg)
	if f.runOverride != nil {
		return f.runOut[arg], f.runOverride(arg)
	}
	return f.runOut[arg], f.runErr[arg]
}

func (f *fakeSystem) ServiceRunning(string) (bool, bool, error) {
	return f.svcExists, f.svcRunning, f.svcErr
}

func (f *fakeSystem) RecentEventIDs(context.Context, string, ...int) ([]int, error) {
	f.eventCalls++
	return f.events, f.eventsErr
}

func rpcManager(t *testing.T, f *fakeSystem) (*Manager, string) {
	t.Helper()
	conf := filepath.Join(t.TempDir(), "RpcFw.conf")
	return New(RPCSpec(`C:\adaegis\rpcfw\rpcFwManager.exe`, conf), f), conf
}

func TestInstalledAndName(t *testing.T) {
	m, _ := rpcManager(t, &fakeSystem{installed: true})
	if m.Name() != "rpcfw" || !m.Installed() {
		t.Fatal("name/installed")
	}
	m2, _ := rpcManager(t, &fakeSystem{installed: false})
	if m2.Installed() {
		t.Fatal("should report not installed")
	}
}

func TestStartStopArgs(t *testing.T) {
	f := &fakeSystem{installed: true}
	m, _ := rpcManager(t, f)
	ctx := context.Background()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	if strings.Join(f.calls, ",") != "/start,/stop" {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestStartWrapsManagerOutput(t *testing.T) {
	f := &fakeSystem{
		runErr: map[string]error{"/start": errors.New("exit 1")},
		runOut: map[string]string{"/start": "Error: could not obtain SeSecurityPrivilege."},
	}
	m, _ := rpcManager(t, f)
	err := m.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "rpcfw /start") || !strings.Contains(err.Error(), "SeSecurityPrivilege") {
		t.Fatalf("err=%v", err)
	}
}

func TestApplyConfigWritesAndReloads(t *testing.T) {
	f := &fakeSystem{}
	m, conf := rpcManager(t, f)
	cfg := []byte("fw:uuid:e3514235-4b06-11d1-ab04-00c04fc2dcd2 opnum:3 action:block audit:true\n")
	if err := m.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(conf)
	if string(got) != string(cfg) {
		t.Fatalf("written=%q", got)
	}
	if strings.Join(f.calls, ",") != "/update" {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestApplyConfigRejectsInvalidBeforeWriteOrReload(t *testing.T) {
	f := &fakeSystem{}
	m, conf := rpcManager(t, f)
	os.WriteFile(conf, []byte("fw:action:allow audit:true\n"), 0o644)
	if err := m.ApplyConfig(context.Background(), []byte("fw:action:permit\n")); err == nil {
		t.Fatal("expected rejection")
	}
	if len(f.calls) != 0 {
		t.Fatalf("manager must not run for invalid config, calls=%v", f.calls)
	}
	got, _ := os.ReadFile(conf)
	if string(got) != "fw:action:allow audit:true\n" {
		t.Fatalf("existing config changed: %q", got)
	}
}

func TestApplyConfigRollsBackWhenReloadRejected(t *testing.T) {
	old := []byte("fw:action:allow audit:true\n")
	f := &fakeSystem{}
	m, conf := rpcManager(t, f)
	os.WriteFile(conf, old, 0o644)

	updates := 0
	f.runOverride = func(arg string) error {
		if arg == "/update" {
			updates++
			if updates == 1 {
				return errors.New("firewall rejected config")
			}
		}
		return nil
	}
	err := m.ApplyConfig(context.Background(), []byte("fw:action:block audit:true\n"))
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("err=%v", err)
	}
	if updates != 2 {
		t.Fatalf("expected apply + rollback reload, got %d", updates)
	}
	got, _ := os.ReadFile(conf)
	if string(got) != string(old) {
		t.Fatalf("expected rollback to old, got %q", got)
	}
}

func TestApplyConfigRemovesFileWhenNoPriorAndReloadFails(t *testing.T) {
	f := &fakeSystem{runErr: map[string]error{"/update": errors.New("x")}}
	m, conf := rpcManager(t, f)
	if err := m.ApplyConfig(context.Background(), []byte("fw:action:block\n")); err == nil {
		t.Fatal("expected error")
	}
	if _, err := os.Stat(conf); !os.IsNotExist(err) {
		t.Fatal("expected file removed when no prior config existed")
	}
}

func TestLDAPApplyUsesJSONValidator(t *testing.T) {
	f := &fakeSystem{}
	conf := filepath.Join(t.TempDir(), "config.json")
	m := New(LDAPSpec(`C:\adaegis\ldapfw\ldapFwManager.exe`, conf), f)
	if err := m.ApplyConfig(context.Background(), []byte(`{"rules":[{"operations":["reed"]}]}`)); err == nil {
		t.Fatal("unknown op must be rejected")
	}
	if len(f.calls) != 0 {
		t.Fatal("no manager call for invalid json")
	}
	if err := m.ApplyConfig(context.Background(), []byte(`{"rules":[{"operations":["search"],"attributes":["admincount"],"audit":"on"}]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestProtectionActiveAndStatus(t *testing.T) {
	cases := []struct {
		name            string
		installed       bool
		running         bool
		events          []int
		wantProtected   bool
		wantEventlookup bool
	}{
		{"added newest", true, true, []int{1, 2}, true, true},
		{"removed newest", true, true, []int{2, 1}, false, true},
		{"only audits", true, true, []int{3, 3}, false, true},
		{"no events", true, true, nil, false, true},
		{"service stopped", true, false, []int{1}, false, false},
	}
	for _, c := range cases {
		f := &fakeSystem{installed: c.installed, svcExists: true, svcRunning: c.running, events: c.events}
		m, _ := rpcManager(t, f)
		act, err := m.ProtectionActive(context.Background())
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if act != c.wantProtected {
			t.Errorf("%s: protected=%v want %v", c.name, act, c.wantProtected)
		}
		st, err := m.Status(context.Background())
		if err != nil {
			t.Fatalf("%s status: %v", c.name, err)
		}
		if st.Running != c.running || st.Protected != c.wantProtected {
			t.Errorf("%s: status=%+v", c.name, st)
		}
		if c.wantEventlookup && f.eventCalls == 0 {
			t.Errorf("%s: expected event lookup", c.name)
		}
		if !c.wantEventlookup && f.eventCalls != 0 {
			t.Errorf("%s: event log must not be queried", c.name)
		}
	}
}

func TestStatusNotInstalledSkipsEverything(t *testing.T) {
	f := &fakeSystem{installed: false, svcExists: true, svcRunning: true, events: []int{1}}
	m, _ := rpcManager(t, f)
	st, err := m.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if st.Installed || st.Running || st.Protected || f.eventCalls != 0 {
		t.Fatalf("not installed should short-circuit, st=%+v calls=%d", st, f.eventCalls)
	}
}

func TestStatusSurfacesServiceAndEventErrors(t *testing.T) {
	f := &fakeSystem{installed: true, svcErr: errors.New("scm down")}
	m, _ := rpcManager(t, f)
	if _, err := m.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "scm down") {
		t.Fatalf("expected service error, got %v", err)
	}

	f2 := &fakeSystem{installed: true, svcExists: true, svcRunning: true, eventsErr: errors.New("channel missing")}
	m2, _ := rpcManager(t, f2)
	st, err := m2.Status(context.Background())
	if err == nil || !strings.Contains(err.Error(), "channel missing") {
		t.Fatalf("expected event error, got %v", err)
	}
	if !st.Running || st.Protected {
		t.Fatalf("running reported, protection not assumed on error: %+v", st)
	}
}

func TestLDAPUsesOwnEventIDs(t *testing.T) {
	f := &fakeSystem{installed: true, svcExists: true, svcRunning: true, events: []int{257}}
	m := New(LDAPSpec("x", filepath.Join(t.TempDir(), "c.json")), f)
	if act, _ := m.ProtectionActive(context.Background()); !act {
		t.Fatal("257 newest => protected")
	}
	f.events = []int{258, 257}
	if act, _ := m.ProtectionActive(context.Background()); act {
		t.Fatal("258 newest => not protected")
	}
}
