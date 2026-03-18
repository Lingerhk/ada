package worker

import (
	"ada/backend/common"
	"ada/backend/model"
	"ada/backend/tasker/config"
	"context"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RichardKnop/machinery/v2"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type Worker struct {
	env *config.Env
}

func New(env *config.Env) *Worker {
	return &Worker{env}
}

func (w *Worker) WithContext(ctx context.Context) *Worker {
	return w.withContext(ctx)
}

func (w *Worker) GetLanguage() string {
	// get system language settings
	var sysInfo model.SystemInfo
	err, exist := w.env.MongoCli.FindOne(sysInfo.CollectName(), bson.M{}, &sysInfo)
	if err != nil || !exist {
		return common.LangEn
	}
	return sysInfo.SystemLanguage
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
