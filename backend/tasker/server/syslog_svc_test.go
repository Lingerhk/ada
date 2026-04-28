package server

import "testing"

func TestIsPktlogSyslog(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "pktlog type",
			content: `{"LogType":"pktlog","Source":"tshark"}`,
			want:    true,
		},
		{
			name:    "tshark source",
			content: `{"Source":"tshark"}`,
			want:    true,
		},
		{
			name:    "event log",
			content: `{"EventID":4624}`,
			want:    false,
		},
		{
			name:    "invalid json",
			content: `not-json`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPktlogSyslog(tt.content); got != tt.want {
				t.Fatalf("isPktlogSyslog() = %v, want %v", got, tt.want)
			}
		})
	}
}
