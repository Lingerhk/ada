package gocelery

import (
	"context"
	"testing"
)

func TestNewRedisClientEInvalidURL(t *testing.T) {
	client, err := NewRedisClientE(context.Background(), "://bad-url")
	if err == nil {
		t.Fatal("expected error for invalid redis url")
	}
	if client != nil {
		t.Fatal("expected nil client on invalid redis url")
	}
}

func TestNewRedisClientInvalidURLReturnsNil(t *testing.T) {
	client := NewRedisClient(context.Background(), "://bad-url")
	if client != nil {
		t.Fatal("expected nil client for invalid redis url")
	}
}
