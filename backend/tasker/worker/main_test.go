package worker

import (
	"ada/backend/tasker/config"
	"os"
	"testing"

	logger "github.com/sirupsen/logrus"
)

var WCli *Worker

func TestMain(m *testing.M) {
	logger.Info("starting task_worker(testing) for ADA")

	confPath := os.Getenv("TASKER_CONF_PATH")
	if confPath == "" {
		confPath = "./tasker_test.yaml"
	}

	logger.Infof("load configure from %s", confPath)
	env, err := config.Init(confPath, "worker")
	if err != nil {
		panic(err)
	}

	WCli = New(env)

	os.Exit(m.Run())
}
