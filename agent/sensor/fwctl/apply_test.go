package fwctl

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicApplyWritesWhenValidAndReloadOK(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg")
	reloaded := false
	err := atomicApply(p, []byte("new"), func([]byte) error { return nil }, func() error { reloaded = true; return nil })
	if err != nil {
		t.Fatal(err)
	}
	if !reloaded {
		t.Fatal("reload not called")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "new" {
		t.Fatalf("got %q", got)
	}
}

func TestAtomicApplyRejectsInvalid(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg")
	os.WriteFile(p, []byte("old"), 0o644)
	err := atomicApply(p, []byte("bad"), func([]byte) error { return errors.New("nope") }, func() error { t.Fatal("reload must not run"); return nil })
	if err == nil {
		t.Fatal("expected validation error")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "old" {
		t.Fatalf("file should be unchanged, got %q", got)
	}
}

func TestAtomicApplyRollsBackOnReloadFailure(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg")
	os.WriteFile(p, []byte("old"), 0o644)
	reloads := 0
	err := atomicApply(p, []byte("new"), nil, func() error {
		reloads++
		if reloads == 1 {
			return errors.New("reload rejected")
		}
		return nil // rollback reload succeeds
	})
	if err == nil {
		t.Fatal("expected reload error")
	}
	got, _ := os.ReadFile(p)
	if string(got) != "old" {
		t.Fatalf("expected rollback to old content, got %q", got)
	}
	if reloads != 2 {
		t.Fatalf("expected reload called twice (apply+rollback), got %d", reloads)
	}
}

func TestAtomicApplyRemovesFileOnReloadFailureWhenNoBackup(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg")
	err := atomicApply(p, []byte("new"), nil, func() error { return errors.New("x") })
	if err == nil {
		t.Fatal("expected error")
	}
	if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
		t.Fatal("expected file removed when there was no prior config")
	}
}
