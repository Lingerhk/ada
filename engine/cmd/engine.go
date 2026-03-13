package main

import (
	"ada/engine/config"
	"ada/engine/core"
	_ "ada/infra/version"
	"os"
	"os/signal"
	"syscall"

	logger "github.com/sirupsen/logrus"
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
		logger.Errorf("init engine config failed: %v", err)
		os.Exit(1)
	}

	e, err := core.New(env)
	if err != nil {
		logger.Errorf("init engine worker failed: %v", err)
		os.Exit(1)
	}

	if err := e.Setup(); err != nil {
		logger.Errorf("setup engine worker failed: %v", err)
		os.Exit(1)
	}

	go e.RuntimeCheck() // license check

	// signal handler: exit and reload
	go signalHandler(e)

	// Redis pub/sub rule reload listener
	go e.RuleReloader()

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

	for {
		ch := <-c
		logger.Infof("ada_engine received %s signal", ch.String())

		switch ch {
		case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
			logger.Info("ada_engine shutting down...")
			e.Stop()
			return
		case syscall.SIGHUP:
			logger.Info("Reloading rules due to SIGHUP signal")
			if err := e.Reload(); err != nil {
				logger.Errorf("Failed to reload rules: %v", err)
				os.Exit(1)
			}
		default:
			logger.Warnf("Received unexpected signal: %s", ch.String())
		}
	}
}
