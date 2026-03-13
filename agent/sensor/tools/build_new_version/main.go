//go:build tools

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

	sha256sum := sha256.Sum256(binBytes)
	sum := fmt.Sprintf("%x", sha256sum)
	fmt.Printf("sha256sum:%s\n", sum)

	ctxData := map[string]string{
		"bin_file":   string(binBytes),
		"version":    NewVersion,
		"sha256_sum": sum,
	}
	if err := rdx.HSet(ctx, common.SensorBinVerPrefix, ctxData).Err(); err != nil {
		panic(err)
	}
}
