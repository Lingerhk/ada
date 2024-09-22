package file

import (
	"os"
	"testing"
)

func TestZip(t *testing.T) {

	pkgDir := "/tmp/2.dir"
	// 打包为 zip 文件
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
	file, err := os.OpenFile("/Users/test/1.zip", os.O_CREATE|os.O_RDWR, os.ModePerm)
	if err != nil {
		t.Fatal(err)
	}
	if err := DeCompress(file, "./zip"); err != nil {
		t.Fatal(err)
	}
}
