package worker

import (
	"ada/backend/tasker/config"
	"fmt"
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
		fmt.Fprintf(os.Stderr, "skipping ada/backend/tasker/worker: test environment unavailable: %v\n", err)
		os.Exit(0)
	}

	WCli = New(env)

	os.Exit(m.Run())
}
