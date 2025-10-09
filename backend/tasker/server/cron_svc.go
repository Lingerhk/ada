package server

import (
	"ada/backend/model"
	"ada/backend/tasker/common"
	"ada/backend/tasker/tasks"
	"fmt"
	"reflect"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"
	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/bson"
)

// Define CycleType constants based on model.ScanConf.CycleType (int32)
const (
	typeDaily   int32 = 1
	typeWeekly  int32 = 2
	typeMonthly int32 = 3
)

// CronScheduler holds the gocron scheduler and tasker instance
type CronScheduler struct {
	Server       gocron.Scheduler
	Tasker       *TaskServer
	CjIdMap      map[string]gocron.Job
	CjVersionMap map[string]time.Time
}

// NewCronScheduler creates a new cron scheduler
func NewCronScheduler(ts *TaskServer) (*CronScheduler, error) {
	s, err := gocron.NewScheduler(gocron.WithLocation(time.Local))
	if err != nil {
		logger.Errorf("Failed to create cron scheduler: %v", err)
		return nil, err
	}

	return &CronScheduler{
		Server:       s,
		Tasker:       ts,
		CjIdMap:      make(map[string]gocron.Job),
		CjVersionMap: make(map[string]time.Time),
	}, nil
}

// CronTaskServe sets up initial cron jobs and starts the scheduler
func (cs *CronScheduler) CronTaskServe() {
	// Create initial jobs using v2 API
	_, err := cs.Server.NewJob(
		gocron.DurationJob(time.Duration(common.CronDomainSyncPeriod)*time.Second),
		gocron.NewTask(cs.Tasker.taskSrv.SendTask, tasks.TaskDomainSync()),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		logger.Errorf("Failed to create DomainSync job: %v", err)
	}

	_, err = cs.Server.NewJob(
		gocron.DurationJob(time.Duration(common.CronSystemSyncPeriod)*time.Second),
		gocron.NewTask(cs.Tasker.taskSrv.SendTask, tasks.TaskSystemSync()),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		logger.Errorf("Failed to create SystemSync job: %v", err)
	}

	_, err = cs.Server.NewJob(
		gocron.DurationJob(time.Duration(common.CronADLdapSyncPeriod)*time.Second),
		gocron.NewTask(cs.Tasker.taskSrv.SendTask, tasks.TaskADLdapSync()),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		logger.Errorf("Failed to create ADLdapSync job: %v", err)
	}

	_, err = cs.Server.NewJob(
		gocron.DurationJob(time.Duration(common.CronThreatNotifyPeriod)*time.Second),
		gocron.NewTask(cs.Tasker.taskSrv.SendTask, tasks.TaskThreatNotify()),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		logger.Errorf("Failed to create ThreatNotify job: %v", err)
	}

	_, err = cs.Server.NewJob(
		gocron.DurationJob(time.Duration(common.CronSystemNotifyPeriod)*time.Second),
		gocron.NewTask(cs.Tasker.taskSrv.SendTask, tasks.TaskSystemNotify()),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		logger.Errorf("Failed to create SystemNotify job: %v", err)
	}

	go cs.CronJobUpdate() // Start dynamic job updater
	cs.Server.Start()
}

// Stop stops the cron scheduler
func (cs *CronScheduler) Stop() {
	cs.Server.Shutdown()
}

// createScheduledJob creates a gocron job based on config using v2 API
func (cs *CronScheduler) createScheduledJob(jobConf *model.ScanConf) (gocron.Job, error) {
	jobID := jobConf.ID.Hex()

	// Create task function that will be executed
	taskToRun := func() {
		logger.Infof("Executing task: %s for job ID: %s, CycleType: %d", jobConf.TaskFun, jobID, jobConf.CycleType)
		method := reflect.ValueOf(cs.Tasker).MethodByName(jobConf.TaskFun)
		if method.IsValid() {
			method.Call([]reflect.Value{})
		} else {
			logger.Errorf("Task function %s not found for job ID: %s", jobConf.TaskFun, jobID)
		}
	}

	// Parse time to get hour and minute
	hour, minute, err := parseTimeString(jobConf.RunTime)
	if err != nil {
		logger.Errorf("failed to parse run time: %v", err)
		return nil, err
	}

	var jobDef gocron.JobDefinition

	switch jobConf.CycleType {
	case typeDaily:
		jobDef = gocron.DailyJob(1, gocron.NewAtTimes(
			gocron.NewAtTime(uint(hour), uint(minute), 0),
		))
	case typeWeekly:
		// Run every Monday at specified time
		jobDef = gocron.WeeklyJob(1, gocron.NewWeekdays(time.Monday), gocron.NewAtTimes(
			gocron.NewAtTime(uint(hour), uint(minute), 0),
		))
	case typeMonthly:
		// Run on 1st day of month at specified time
		jobDef = gocron.MonthlyJob(1, gocron.NewDaysOfTheMonth(1), gocron.NewAtTimes(
			gocron.NewAtTime(uint(hour), uint(minute), 0),
		))
	default:
		return nil, fmt.Errorf("unsupported cycle type: %d", jobConf.CycleType)
	}

	task := gocron.NewTask(taskToRun, jobConf.Plans)
	job, err := cs.Server.NewJob(
		jobDef,
		task,
		gocron.WithTags(jobID),
		gocron.WithSingletonMode(gocron.LimitModeReschedule),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create scheduled job: %w", err)
	}

	return job, nil
}

// parseTimeString parses time string like "02:00" to hour and minute
func parseTimeString(timeStr string) (int, int, error) {
	parts := strings.Split(timeStr, ":")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("invalid time format: %s", timeStr)
	}

	hour, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid hour: %s", parts[0])
	}

	minute, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minute: %s", parts[1])
	}

	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return 0, 0, fmt.Errorf("invalid time values: %02d:%02d", hour, minute)
	}

	return hour, minute, nil
}

// loadJobConfigsFromDB reads all enabled scan configurations from database
func (cs *CronScheduler) loadJobConfigsFromDB() ([]*model.ScanConf, error) {
	var jobList []*model.ScanConf
	filter := bson.M{"is_enable": true}

	if err := cs.Tasker.env.MongoCli.FindAll((&model.ScanConf{}).CollectName(), filter, &jobList); err != nil {
		return nil, fmt.Errorf("failed to query scan configs: %w", err)
	}

	return jobList, nil
}

// removeJobByID removes a job from scheduler and internal maps
func (cs *CronScheduler) removeJobByID(jobID string) {
	// Find and remove job by ID from our map
	if job, exists := cs.CjIdMap[jobID]; exists {
		if err := cs.Server.RemoveJob(job.ID()); err != nil {
			logger.Warnf("CronJobUpdate: Failed to remove job %s: %v", jobID, err)
		}
	}

	// Remove from our internal maps
	delete(cs.CjIdMap, jobID)
	delete(cs.CjVersionMap, jobID)
}

// CronJobUpdate dynamically updates cron jobs based on tb_scan_conf
func (cs *CronScheduler) CronJobUpdate() {
	defer func() {
		if e := recover(); e != nil {
			logger.Errorf("CronJobUpdate crashed, err: %s\ntrace:%s", e, string(debug.Stack()))
		}
	}()

	for {
		time.Sleep(1 * time.Minute)
		logger.Debug("CronJobUpdate running...")

		// Load job configurations from database
		jobConfigs, err := cs.loadJobConfigsFromDB()
		if err != nil {
			logger.Errorf("loadJobConfigsFromDB error: %v", err)
			continue
		}

		// Track which jobs should be active
		activeJobIDs := make(map[string]bool)

		// Process each job configuration
		for _, jobConf := range jobConfigs {
			jobID := jobConf.ID.Hex()
			activeJobIDs[jobID] = true

			localUpdateTm, jobExists := cs.CjVersionMap[jobID]

			// Check if job needs to be created or updated
			if !jobExists || localUpdateTm.Before(jobConf.UpdateTm) {
				logger.Infof("CronJobUpdate: %s job ID %s (TaskFun: %s, Cycle: %d, Time: %s)",
					map[bool]string{true: "Updating", false: "Creating"}[jobExists],
					jobID, jobConf.TaskFun, jobConf.CycleType, jobConf.RunTime)

				// Remove existing job if it exists
				if jobExists {
					cs.removeJobByID(jobID)
				}

				// Create new job
				newJob, err := cs.createScheduledJob(jobConf)
				if err != nil {
					logger.Errorf("CronJobUpdate: Failed to create job ID %s: %v", jobID, err)
					continue
				}

				// Store job reference and version
				cs.CjIdMap[jobID] = newJob
				cs.CjVersionMap[jobID] = jobConf.UpdateTm

				logger.Infof("CronJobUpdate: Successfully scheduled job %s (%s) - Cycle: %d, Time: %s",
					jobConf.Name, jobConf.TaskFun, jobConf.CycleType, jobConf.RunTime)
			}
		}

		// Remove jobs that are no longer in config or were disabled
		for jobIDInMap := range cs.CjIdMap {
			if !activeJobIDs[jobIDInMap] {
				logger.Infof("CronJobUpdate: Removing stale/disabled job ID %s", jobIDInMap)
				cs.removeJobByID(jobIDInMap)
			}
		}

		logger.Debugf("CronJobUpdate: Managing %d active jobs", len(cs.CjIdMap))
	}
}
