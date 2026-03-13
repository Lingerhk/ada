package main

import (
	"ada/infra/license"
	_ "ada/infra/version"
	"ada/scanner/common"
	"ada/scanner/config"
	"ada/scanner/worker"
	logger "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	logger.Info("starting ada_scanner for ADA")
	confPath := os.Getenv(common.ScannerConfPathEnv)
	if confPath == "" {
		confPath = common.ScannerDefaultConfPath
	}

	logger.Infof("load configure from %s", confPath)
	env, err := config.Init(confPath)
	if err != nil {
		logger.Errorf("init scanner config failed: %v", err)
		os.Exit(1)
	}

	logger.Debugf("trait: %s", license.GetTrait())

	w, err := worker.New(env)
	if err != nil {
		logger.Errorf("init scanner worker failed: %v", err)
		os.Exit(1)
	}

	if err = w.Setup(); err != nil {
		logger.Errorf("setup scanner worker failed: %v", err)
		os.Exit(1)
	}

	// signal handler: exit
	go signalHandler(w)

	go w.RuntimeCheck()

	w.Worker()
}

// signal handler
func signalHandler(w *worker.ScanSvc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	ch := <-c

	logger.Infof("ada_scanner get %s signal", ch.String())
	switch ch {
	case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
		logger.Info("ada_scanner exit")
		w.Stop()
		return
	case syscall.SIGHUP:
		// TODO reload
	default:
		return
	}
}
