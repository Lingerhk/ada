//go:build tools

package main

import (
	"ada/infra/file"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	pkgDir = "C:\\Users\\admin\\ada\\agent\\package"
)

var pkgFiles = []string{
	"nxlog-ce-3.2.msi",
	"npcap-0.93.exe",
	"ntap_remote.exe",
	"ada_sensor.exe",
	"sensor.cfg",
	"nxlog.conf",
	"rpcfw.zip",
	"ldapfw.zip",
}

var rdx *redis.Client

func init() {
	opt := redis.Options{
		Addr:         "192.168.18.4:6379",
		Password:     "1pa2YgE3jfTbVVpn06CN",
		DialTimeout:  30 * time.Second,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}
	rdx = redis.NewClient(&opt)
}

func main() {
	ctx := context.Background()

	for _, item := range pkgFiles {
		fpath := filepath.Join(pkgDir, item)
		fd, err := os.Open(fpath)
		if err != nil {
			panic(err)
		}

		content, err := io.ReadAll(fd)
		fd.Close()
		if err != nil {
			panic(err)
		}

		sum := fmt.Sprintf("%x", sha256.Sum256(content))
		if err := rdx.HSet(ctx, "ada:sensor:pkg", item, string(content)).Err(); err != nil {
			panic(err)
		}
		if err := rdx.HSet(ctx, "ada:sensor:pkg:sha256", item, sum).Err(); err != nil {
			panic(err)
		}
	}

	if err := file.Zip(filepath.Join(pkgDir, "sensor.zip"), pkgDir, pkgFiles...); err != nil {
		panic(err)
	}
}
