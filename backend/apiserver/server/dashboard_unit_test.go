package server

import "testing"

func TestAlertLevelKey(t *testing.T) {
	tests := []struct {
		name  string
		level int32
		key   string
		ok    bool
	}{
		{name: "critical", level: 5, key: "high", ok: true},
		{name: "high", level: 4, key: "high", ok: true},
		{name: "medium", level: 3, key: "medium", ok: true},
		{name: "low", level: 2, key: "low", ok: true},
		{name: "info ignored", level: 1, key: "", ok: false},
		{name: "unknown ignored", level: 0, key: "", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, ok := alertLevelKey(tt.level)
			if ok != tt.ok {
				t.Fatalf("expected ok=%v, got %v", tt.ok, ok)
			}
			if key != tt.key {
				t.Fatalf("expected key %q, got %q", tt.key, key)
			}
		})
	}
}

func TestMatchDomainSuffix(t *testing.T) {
	domains := []string{"sevenkingdoms.local", "north.example"}

	tests := []struct {
		hostname string
		want     string
	}{
		{hostname: "kingslanding.sevenkingdoms.local", want: "sevenkingdoms.local"},
		{hostname: "SEVENKINGDOMS.LOCAL", want: "sevenkingdoms.local"},
		{hostname: "winterfell.north.example", want: "north.example"},
		{hostname: "north.example.evil", want: ""},
		{hostname: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.hostname, func(t *testing.T) {
			if got := matchDomain(tt.hostname, domains); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}

func TestDomainHostnameFilterSkipsEmptyDomains(t *testing.T) {
	if _, ok := domainHostnameFilter([]string{"", "  "}); ok {
		t.Fatal("expected empty filter for blank domains")
	}
	if _, ok := domainHostnameFilter([]string{"sevenkingdoms.local"}); !ok {
		t.Fatal("expected filter for non-empty domain")
	}
}
