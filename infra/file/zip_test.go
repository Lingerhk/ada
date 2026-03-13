package file

import (
	"os"
	"path/filepath"
	"testing"
)

func TestZip(t *testing.T) {
	pkgDir := t.TempDir()
	testFile := filepath.Join(pkgDir, "sample.txt")
	if err := os.WriteFile(testFile, []byte("sample"), 0644); err != nil {
		t.Fatal(err)
	}
	// Package as zip file
	files, err := GetFilesFromDir(pkgDir)
	if err != nil {
		t.Fatal(err)
	}
	spiderZipFileName := "./2.zip"
	if err := Compress(files, spiderZipFileName); err != nil {
		t.Fatal(err)
	}
}

func TestDeCompress(t *testing.T) {
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "sample.txt")
	if err := os.WriteFile(srcFile, []byte("sample"), 0644); err != nil {
		t.Fatal(err)
	}
	files, err := GetFilesFromDir(srcDir)
	if err != nil {
		t.Fatal(err)
	}
	zipPath := filepath.Join(t.TempDir(), "sample.zip")
	if err := Compress(files, zipPath); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(zipPath, os.O_RDONLY, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := DeCompress(file, filepath.Join(t.TempDir(), "zip")); err != nil {
		t.Fatal(err)
	}
}
