package net

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

func CheckPortOpen(ip string, port int) (bool, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), time.Second*5)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return true, nil
}

// NewHTTPClient creates an HTTP client with timeout mechanism, usage: NewHTTPClient(2)
func NewHTTPClient(timeout int64) *http.Client {
	client := &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
				deadline := time.Now().Add(time.Duration(timeout) * time.Second)
				c, err := net.DialTimeout(netw, addr, time.Second*time.Duration(timeout))
				if err != nil {
					return nil, err
				}
				err = c.SetDeadline(deadline)
				return c, err
			},
			ResponseHeaderTimeout: time.Second * time.Duration(timeout),
		},
	}
	return client
}

// NewHTTPClientWithProxy creates an HTTP client with timeout and proxy support
// proxyURL: HTTP proxy URL (e.g., "http://proxy.example.com:8080")
// timeout: request timeout in seconds
func NewHTTPClientWithProxy(proxyURL string, timeout int64) *http.Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, netw, addr string) (net.Conn, error) {
			deadline := time.Now().Add(time.Duration(timeout) * time.Second)
			c, err := net.DialTimeout(netw, addr, time.Second*time.Duration(timeout))
			if err != nil {
				return nil, err
			}
			err = c.SetDeadline(deadline)
			return c, err
		},
		ResponseHeaderTimeout: time.Second * time.Duration(timeout),
	}

	// Set proxy if provided
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxy)
		}
	}

	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
	}
}
