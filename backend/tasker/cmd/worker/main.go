package main

import (
	"ada/backend/tasker/config"
	"ada/backend/tasker/server"
	"ada/backend/tasker/worker"
	_ "ada/infra/version"
	logger "github.com/sirupsen/logrus"
	"os"
)

func main() {
	logger.Info("starting ada_tasker(worker) for ADA")
	confPath := os.Getenv("TASKER_CONF_PATH")
	if confPath == "" {
		confPath = "./tasker.yaml"
	}

	logger.Infof("load configure from %s", confPath)
	env, err := config.Init(confPath, "worker")
	if err != nil {
		logger.Errorf("init tasker worker config failed: %v", err)
		os.Exit(1)
	}

	machineryServer, err := server.MachineryServer(env, "ada:tasker:task_queue")
	if err != nil {
		logger.Errorf("init tasker worker machinery server failed: %v", err)
		os.Exit(1)
	}

	w := worker.NewTaskWorker(env, machineryServer)

	go w.SignalHandler()

	if err := w.Start(); err != nil {
		logger.Errorf("start tasker worker failed: %v", err)
		os.Exit(1)
	}
}
