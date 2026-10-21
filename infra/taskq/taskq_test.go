package taskq

import "testing"

func TestScannerTaskName(t *testing.T) {
	for in, want := range map[string]string{"baseline": ScannerBaselineTask, "Leak": ScannerLeakTask, " weakpwd ": ScannerWeakPwdTask} {
		got, err := ScannerTaskName(in)
		if err != nil || got != want {
			t.Errorf("ScannerTaskName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ScannerTaskName("recheck"); err == nil {
		t.Error("unknown scan type should fail")
	}
}

func TestScannerPayloadRoundTrip(t *testing.T) {
	sig, err := NewScannerSignature("baseline", "sub-1", map[string]any{"domain": "corp.local", "plugin_id": 1001})
	if err != nil {
		t.Fatal(err)
	}
	if sig.Name != ScannerBaselineTask || sig.RoutingKey != ScannerQueue || len(sig.Args) != 1 {
		t.Fatalf("unexpected signature %+v", sig)
	}
	p, err := DecodeScannerPayload(sig.Args[0].Value.(string))
	if err != nil {
		t.Fatal(err)
	}
	if p.TaskID != "sub-1" || p.Kwargs["domain"] != "corp.local" || p.Kwargs["plugin_id"] != float64(1001) {
		t.Fatalf("unexpected payload %+v", p)
	}
	if _, err := DecodeScannerPayload("{"); err == nil {
		t.Error("invalid json should fail")
	}
}

func TestNewServer(t *testing.T) {
	if _, err := NewServer("redis://:pass@localhost:6379/2", TaskerQueue); err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if _, err := NewServer("not a uri", TaskerQueue); err == nil {
		t.Error("invalid uri should fail")
	}
}
