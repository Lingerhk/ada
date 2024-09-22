package worker

import (
	"ada/backend/tasker/config"
	"github.com/RichardKnop/machinery/v2"
	logger "github.com/sirupsen/logrus"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type Worker struct {
	env *config.Env
}

func New(env *config.Env) *Worker {
	return &Worker{env}
}

type TaskWorker struct {
	env    *config.Env
	server *machinery.Server
	worker *machinery.Worker
}

func NewTaskWorker(env *config.Env, ms *machinery.Server) *TaskWorker {
	worker := ms.NewWorker("ada_tasker_worker", 64)

	return &TaskWorker{env, ms, worker}
}

func (tw *TaskWorker) Start() error {
	// // set error hooks
	errorHandler := func(err error) {
		logger.Errorf("error handler:%v", err)
	}
	tw.worker.SetErrorHandler(errorHandler)

	return tw.worker.Launch()
}

func (tw *TaskWorker) Stop() {
	tw.worker.Quit()
}

// signal handler
func (tw *TaskWorker) SignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT)
	ch := <-c

	logger.Infof("tasker(worker) get %s signal", ch.String())
	switch ch {
	case syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGINT:
		logger.Info("tasker(worker) exit")
		tw.Stop()
		time.Sleep(time.Second)
		return
	case syscall.SIGHUP:
		// TODO reload
	default:
		return
	}
}
