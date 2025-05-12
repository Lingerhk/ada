package main

import (
	"ada/agent/sensor/common"
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/redis/go-redis/v9"
	"io"
	"os"
)

const (
	SensorPath = "ada_sensor.exe"
	NewVersion = "2.6.0"
)

func main() {
	opt := redis.Options{
		Addr:     "192.168.18.4:6379",
		Password: "1pa2YgE3jfTbVVpn06CN",
	}

	rdx := redis.NewClient(&opt)
	err := rdx.Ping(context.Background()).Err()
	if err != nil {
		panic(err)
	}

	ctx := context.Background()

	file, err := os.OpenFile(SensorPath, os.O_RDONLY, 0666)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()
	binBytes, err := io.ReadAll(file)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}
	err = rdx.Set(ctx, common.SensorLatestBinFileKey, binBytes, 0).Err()
	if err != nil {
		fmt.Println("redis set binfile err:", err)
		return
	}

	hash := sha256.New()
	hash.Write(binBytes)
	sumStr := fmt.Sprintf("%x", hash.Sum(nil))

	err = rdx.Set(ctx, common.SensorLatestBinSumKey, sumStr, 0).Err()
	if err != nil {
		fmt.Println("redis set binsum err:", err)
		return
	}

	err = rdx.Set(ctx, common.SensorLatestVersionKey, NewVersion, 0).Err()
	if err != nil {
		fmt.Println("redis set latest version err:", err)
		return
	}

	fmt.Printf("finished push new version:%s, checksum:%x\n", NewVersion, sumStr)
}
