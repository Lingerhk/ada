package svcconfig

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadYAML(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "c.yaml")
	if err := os.WriteFile(p, []byte("ProjectName: x\nRedis:\n  URI: redis://localhost:6379/0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		ProjectName string   `yaml:"ProjectName"`
		Redis       RedisCfg `yaml:"Redis"`
	}
	if err := LoadYAML(p, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ProjectName != "x" || cfg.Redis.URI != "redis://localhost:6379/0" {
		t.Fatalf("unexpected %+v", cfg)
	}
	if err := LoadYAML(filepath.Join(dir, "missing.yaml"), &cfg); err == nil {
		t.Error("missing file should fail")
	}
}

func TestCtx(t *testing.T) {
	var zero Ctx
	if zero.Context() != context.Background() {
		t.Error("zero Ctx should return Background")
	}
	ctx := context.WithValue(context.Background(), struct{}{}, 1)
	c := zero.With(ctx)
	if c.Context() != ctx {
		t.Error("With should bind ctx")
	}
	if c.With(nil).Context() != ctx {
		t.Error("With(nil) should keep the bound ctx")
	}
}

func TestNewElasticsearchClientDisabled(t *testing.T) {
	cli, err := NewElasticsearchClient(ESCfg{Enable: false})
	if err != nil || cli != nil {
		t.Fatalf("disabled ES should return nil, nil; got %v, %v", cli, err)
	}
}

func TestNewRedisClientInvalidURI(t *testing.T) {
	if _, err := NewRedisClient(context.Background(), RedisCfg{URI: "::bad"}); err == nil {
		t.Error("invalid uri should fail")
	}
}
