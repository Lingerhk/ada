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
		panic(err)
	}

	s, err := server.New(env)
	if err != nil {
		panic(err)
	}

	go s.SignalHandler()

	if err := s.Start(); err != nil {
		panic(err)
	}
}
