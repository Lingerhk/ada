package main

import (
	"ada/infra/file"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/redis/go-redis/v9"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"
)

// Sensor 打包并发如redis
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
	err := rdx.Ping(context.Background()).Err()
	if err != nil {
		panic(err)
	}
}

func main() {
	var err error
	var sumMap = make(map[string]string)

	for _, fileN := range pkgFiles {
		filePath := filepath.Join(pkgDir, fileN)
		f, err := os.OpenFile(filePath, os.O_RDONLY, 0666)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer f.Close()
		binBytes, err := io.ReadAll(f)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		hash := sha256.New()
		hash.Write(binBytes)
		sumStr := fmt.Sprintf("%x", hash.Sum(nil))
		sumMap[fileN] = sumStr
	}

	var sumCnt string
	for fileName, sum := range sumMap {
		sumCnt += fmt.Sprintf("%s %s\n", sum, fileName)
	}

	sumFile := filepath.Join(pkgDir, "checksum.txt")
	err = ioutil.WriteFile(sumFile, []byte(sumCnt), 0644)
	if err != nil {
		fmt.Println("write checksum.txt err:", err)
		return
	}

	// zip 压缩
	files, err := file.GetFilesFromDir(pkgDir)
	if err != nil {
		fmt.Println("read files err:", err)
		return
	}

	zipPkg := filepath.Join("C:\\Users\\admin\\ada\\agent\\ada_sensor.zip")
	if err := file.Compress(files, zipPkg); err != nil {
		fmt.Println("zip pkg err:", err)
		return
	}

	// 计算shasum
	zipBytes, err := ioutil.ReadFile(zipPkg)
	if err != nil {
		fmt.Println("read pkg.zip err:", err)
		return
	}

	hash := sha256.New()
	hash.Write(zipBytes)
	zipSumStr := fmt.Sprintf("%x", hash.Sum(nil))

	// 存入redis
	ctx := context.Background()
	err = rdx.Set(ctx, "ada:sensor:latest_pkgsum", zipSumStr, 0).Err()
	if err != nil {
		fmt.Println("redis set latest_pkgsum err:", err)
		return
	}

	err = rdx.Set(ctx, "ada:sensor:latest_pkgfile", zipBytes, 0).Err()
	if err != nil {
		fmt.Println("redis set latest_pkgfile err:", err)
		return
	}

	fmt.Printf("finished release sensor pkg:%s, checksum:%x\n", zipPkg, zipSumStr)
}
