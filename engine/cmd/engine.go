package main

import (
	"ada/engine/config"
	"ada/engine/core"
	_ "ada/infra/version"
	logger "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	logger.Info("starting ada_engine for ADA")
	confPath := os.Getenv("ENGINE_CONF_PATH")
	if confPath == "" {
		confPath = "./engine.yaml"
	}

	logger.Infof("load configure from %s", confPath)
	env, err := config.Init(confPath)
	if err != nil {
		panic(err)
	}

	e, err := core.New(env)
	if err != nil {
		panic(err)
	}

	if err := e.Setup(); err != nil {
		panic(err)
	}

	go e.RuntimeCheck() // license check

	// signal handler: exit
	go signalHandler(e)

	// start flow match handler goroutine
	go e.FlowMatcher()

	// start flow clean handler goroutine
	go e.FlowCleaner()

	// start sigma rule match handler
	e.SigmaMatcher()
}

// signal handler
func signalHandler(e *core.EngineWorker) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	ch := <-c

	logger.Infof("ada_engine get %s signal", ch.String())
	switch ch {
	case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
		logger.Info("ada_engine exit")
		e.Stop()
		return
	case syscall.SIGHUP:
		// TODO reload
	default:
		return
	}
}
