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
		panic(err)
	}

	machineryServer, err := server.MachineryServer(env, "ada:tasker:task_queue")
	if err != nil {
		panic(err)
	}

	w := worker.NewTaskWorker(env, machineryServer)

	go w.SignalHandler()

	if err := w.Start(); err != nil {
		panic(err)
	}
}
