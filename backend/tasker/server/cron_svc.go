package server

import (
	"ada/backend/model"
	"ada/backend/tasker/common"
	"ada/backend/tasker/tasks"
	"github.com/go-co-op/gocron"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
	"reflect"
	"time"
)

type CronScheduler struct {
	Server       *gocron.Scheduler
	Tasker       *TaskServer
	CjIdMap      map[string]*gocron.Scheduler // 上次任务的jobmap， id-Job
	CjVersionMap map[string]time.Time         //上次任务的版本匹配map, id-time
}

func NewCronScheduler(ts *TaskServer) *CronScheduler {
	s := gocron.NewScheduler(time.Local)

	return &CronScheduler{
		Server:       s,
		Tasker:       ts,
		CjIdMap:      make(map[string]*gocron.Scheduler),
		CjVersionMap: make(map[string]time.Time),
	}
}

// 在此添加 定时任务的执行时间点
func (cs *CronScheduler) CronTaskServe() {
	// SingletonMode() 表示单例
	// WaitForSchedule(): 禁止程序启动时立马执行
	cs.Server.Every(common.CronDomainSyncPeriod).Seconds().SingletonMode().Do(cs.Tasker.taskSrv.SendTask, tasks.TaskDomainSync())
	cs.Server.Every(common.CronSystemSyncPeriod).Seconds().SingletonMode().Do(cs.Tasker.taskSrv.SendTask, tasks.TaskSystemSync())
	cs.Server.Every(common.CronADLdapSyncPeriod).Seconds().SingletonMode().Do(cs.Tasker.taskSrv.SendTask, tasks.TaskADLdapSync())
	cs.Server.Every(common.CronThreatNotifyPeriod).Seconds().WaitForSchedule().SingletonMode().Do(cs.Tasker.taskSrv.SendTask, tasks.TaskThreatNotify())
	cs.Server.Every(common.CronSystemNotifyPeriod).Seconds().SingletonMode().Do(cs.Tasker.taskSrv.SendTask, tasks.TaskSystemNotify())

	// 新建定时任务更新的定时器
	// 因为定时任务都是，每天2点执行，所以隔一小时更新即可
	jobUpdateTicker := time.NewTicker(1 * time.Hour)
	defer jobUpdateTicker.Stop()

	go func() {
		for range jobUpdateTicker.C {
			if err := cs.CronJobUpdate(); err != nil {
				logger.Errorf("CronJobUpdate err:%v", err)
				continue
			}
		}
	}()

	cs.Server.StartBlocking()
}

func (cs *CronScheduler) Stop() {
	cs.Server.Stop()
}

const (
	days   = 1
	weeks  = 2
	months = 3
)

func (cs *CronScheduler) CronJobUpdate() error {
	type timeUnit uint8
	logger.Info("CronJobUpdate running...")

	var jobList []*model.ScanConf
	if err := cs.Tasker.env.MongoCli.FindAll((&model.ScanConf{}).CollectName(), bson.M{}, &jobList); err != nil {
		logger.Errorf("get cron job list fail. error: %s", err)
		return err
	}

	for _, j := range jobList {
		// 如果定时任务数据行
		if !j.IsEnable {
			continue
		}

		localUpdateTm, ok := cs.CjVersionMap[j.ID.Hex()]

		if !ok || localUpdateTm.Before(j.UpdateTm) {
			logger.Info("CronJobUpdate update...")

			gj := cs.Server.Every(1)
			cs.CjIdMap[j.ID.Hex()] = gj
			cs.CjVersionMap[j.ID.Hex()] = j.UpdateTm

			gj.Day().At(j.RunTime).SingletonMode().Do(func(j model.ScanConf) {
				if timeUnit(j.CycleType) == weeks && time.Now().Weekday() != time.Monday {
					return
				}
				if timeUnit(j.CycleType) == months && time.Now().Day() != 1 {
					return
				}
				method := reflect.ValueOf(cs.Tasker).MethodByName(j.TaskFun)
				method.Call(nil)
			}, *j)
		}
	}

	return nil
}
