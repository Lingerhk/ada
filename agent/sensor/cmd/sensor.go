package main

import (
	"ada/agent/sensor/common"
	"ada/agent/sensor/config"
	"ada/agent/sensor/plugin"
	"ada/agent/sensor/register"
	"ada/agent/sensor/stats"
	"ada/agent/sensor/upgrade"
	_ "ada/infra/version"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"time"

	winsvc "github.com/kardianos/service"
	logger "github.com/sirupsen/logrus"
)

var (
	isRegister bool   // Existing flag, will be set by -r
	managerIP  string // New flag for manager IP, set by -m
)

func init() {
	// Define flags
	flag.BoolVar(&isRegister, "r", false, "Register the sensor")
	flag.StringVar(&managerIP, "m", "", "Manager IP address")

	// Parse the flags
	flag.Parse()
}

func main() {
	runtime.GOMAXPROCS(4) // 限制CPU

	if managerIP != "" {
		// check if managerIP is valid
		if net.ParseIP(managerIP) == nil {
			fmt.Printf("[sensor] invalid manager ip:%s\n", managerIP)
			os.Exit(-1)
		}

		if err := config.SetManagerIP(managerIP); err != nil {
			fmt.Printf("[sensor] set manager ip(%s) err:%v\n", managerIP, err)
			os.Exit(-1)
		}
		fmt.Printf("[sensor] set manager ip(%s) success!\n", managerIP)
		os.Exit(0)
	}

	env, err := config.Init()
	if err != nil {
		panic(err)
	}

	// if using -r in command, then start register this sensor
	if isRegister {
		if err := register.Register(env.RedisCli, env.Cfg.Sensor.RegCode); err != nil {
			fmt.Printf("[sensor] register sensor(srv:%s) err:%v\n", env.Cfg.Sensor.RegHost, err)
			os.Exit(-1)
		} else {
			fmt.Printf("[sensor] register sensor(srv:%s) success!\n", env.Cfg.Sensor.RegHost)
		}
		os.Exit(0)
	}

	svcConfig := &winsvc.Config{
		Name:        common.SensorSvcName,
		DisplayName: "ADAegis Sensor",
		Description: "ADAegis Sensor for Active Directory Protection",
	}

	prg := &adaSensorSvc{env: env, exit: make(chan struct{})}
	s, err := winsvc.New(prg, svcConfig)
	if err != nil {
		logger.Errorf("service new err:%v", err)
		return
	}

	if err := s.Run(); err != nil {
		logger.Errorf("service run err:%v", err)
	}
}

type adaSensorSvc struct {
	env  *config.Env
	exit chan struct{}
}

func (p *adaSensorSvc) Start(s winsvc.Service) error {
	plugin.TryStopService(common.PlugRpcFwSvcName)
	plugin.TryStopService(common.PlugLdapFwSvcName)

	go p.run()
	return nil
}

func (p *adaSensorSvc) Stop(s winsvc.Service) error {
	close(p.exit)

	time.Sleep(2 * time.Second)

	if winsvc.Interactive() {
		os.Exit(0)
	}
	return nil
}

func (p *adaSensorSvc) run() {
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			logger.Warningf("adaSensorSvc: panic serving %s: %v", string(buf), err)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())

	go launch(ctx, p.env) // 异步
	select {
	case <-p.exit:
		logger.Infof("%s service stop..", common.SensorSvcName)
		cancel()
		time.Sleep(1 * time.Second)
	}
}

func launch(ctx context.Context, env *config.Env) {
	wg := &sync.WaitGroup{}
	wg.Add(5)

	u := upgrade.New(ctx, env.RedisCli)
	if u.Once() {
		// TODO: how to restart self service????
		os.Exit(0)
	}
	go u.Serve(wg) // 监听升级

	p, err := plugin.New(ctx, env.RedisCli, env.SensorId, env.Cfg.Sensor)
	if err != nil {
		logger.Errorf("new plugin err:%v", err)
		return
	}
	go p.Event(wg) // 监听插件事件
	go p.Serve(wg) //监听插件启停

	s := stats.New(ctx, env.RedisCli, env.SensorId)
	go s.Serve(wg, p.PlugProcessMap) // 上报状态

	wg.Wait()
}
