package main

import (
	"ada/backend/tasker/config"
	"ada/backend/tasker/server"
	_ "ada/infra/version"
	logger "github.com/sirupsen/logrus"
	"os"
)

func main() {
	logger.Info("starting ada_tasker(server) for ADA")
	confPath := os.Getenv("TASKER_CONF_PATH")
	if confPath == "" {
		confPath = "./tasker.yaml"
	}

	logger.Infof("load configure from %s", confPath)
	env, err := config.Init(confPath, "server")
	if err != nil {
		logger.Errorf("init tasker server config failed: %v", err)
		os.Exit(1)
	}

	s, err := server.New(env)
	if err != nil {
		logger.Errorf("init tasker server failed: %v", err)
		os.Exit(1)
	}

	go s.SignalHandler()

	if err := s.Start(); err != nil {
		logger.Errorf("start tasker server failed: %v", err)
		os.Exit(1)
	}
}
