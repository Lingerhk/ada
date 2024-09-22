package main

import (
	"ada/agent/sensor/installer"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TODO: 支持参数 /tool, 下载工具;  支持参数/time, 查看DC时间

func main() {
	// setup file name most by: ada-installer_192.168.18.4.exe

	selfPath, err := os.Executable()
	if err != nil {
		panic(err)
	}

	selfName := filepath.Base(selfPath)
	selfExt := filepath.Ext(selfName)
	filePrefix := selfName[0 : len(selfName)-len(selfExt)]
	parts := strings.SplitN(filePrefix, "_", 2)
	if len(parts) < 2 || net.ParseIP(parts[1]) == nil {
		fmt.Println("Get ada server ip from filename failed!")
		time.Sleep(3 * time.Second)
		return
	}

	fmt.Printf("Starting installer for ADA, server:%s\n", parts[1])
	inst := installer.New(parts[1])

	if err := inst.Download(); err != nil {
		fmt.Printf("download sensor err:%v", err)
		os.Exit(-2)
	}

	if err := inst.Deploy(); err != nil {
		fmt.Printf("deploy sensor err:%v", err)
		os.Exit(-3)
	}

	if err := inst.Register(); err != nil {
		fmt.Printf("[Installer] register sensor err:%v", err)
		os.Exit(-4)
	}

	if err := inst.Start(); err != nil {
		fmt.Printf("start sensor err:%v", err)
		os.Exit(-5)
	}

	os.Exit(0)
}
