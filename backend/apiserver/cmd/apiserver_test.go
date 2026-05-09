package main

import (
	"net/http"
	"testing"
)

func TestIsLoopbackRemote(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		want       bool
	}{
		{name: "ipv4 with port", remoteAddr: "127.0.0.1:8801", want: true},
		{name: "ipv6 with port", remoteAddr: "[::1]:8801", want: true},
		{name: "bare loopback", remoteAddr: "127.0.0.1", want: true},
		{name: "remote", remoteAddr: "192.168.7.2:12345", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isLoopbackRemote(tt.remoteAddr); got != tt.want {
				t.Fatalf("isLoopbackRemote(%q) = %v, want %v", tt.remoteAddr, got, tt.want)
			}
		})
	}
}

func TestIsLoopbackRequest(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		want       bool
	}{
		{
			name:       "direct loopback",
			remoteAddr: "127.0.0.1:8801",
			want:       true,
		},
		{
			name:       "nginx forwarded external real ip",
			remoteAddr: "127.0.0.1:49152",
			headers:    map[string]string{"X-Real-IP": "192.168.7.20"},
			want:       false,
		},
		{
			name:       "nginx forwarded external xff",
			remoteAddr: "127.0.0.1:49152",
			headers:    map[string]string{"X-Forwarded-For": "192.168.7.20, 127.0.0.1"},
			want:       false,
		},
		{
			name:       "forwarded loopback only",
			remoteAddr: "127.0.0.1:49152",
			headers:    map[string]string{"X-Real-IP": "127.0.0.1", "X-Forwarded-For": "127.0.0.1, ::1"},
			want:       true,
		},
		{
			name:       "direct remote",
			remoteAddr: "192.168.7.2:49152",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{RemoteAddr: tt.remoteAddr, Header: http.Header{}}
			for key, value := range tt.headers {
				req.Header.Set(key, value)
			}
			if got := isLoopbackRequest(req); got != tt.want {
				t.Fatalf("isLoopbackRequest(%q, %v) = %v, want %v", tt.remoteAddr, tt.headers, got, tt.want)
			}
		})
	}
}
