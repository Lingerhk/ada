package scgo

import (
	"ada/infra/mongo"
	"ada/infra/taskq"
	"ada/scanner/common"
	"ada/scanner/config"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

type Service struct {
	Cfg       *config.Config
	RedisCli  *redis.Client
	MongoCli  mongo.DBAdaptor
	ctx       context.Context
	RunPath   string // e.g. /var/lib/scada
	ScRoot    string // e.g. /var/lib/scada/.sc
	PythonBin string
	Plugins   *PluginIndex
}

// scanTask is implemented by BaselineTask, LeakTask and WeakPwdTask.
type scanTask interface {
	ParseKwargs(kwargs map[string]any) error
	RunTask() (any, error)
}

func NewService(env *config.Env, runPath string) (*Service, error) {
	scRoot := filepath.Join(runPath, ".sc")
	py := FindPythonBin(runPath)
	if py == "" {
		return nil, fmt.Errorf("python not found under %s/.venv/bin (and no system python)", runPath)
	}
	idx, err := BuildPluginIndex(scRoot)
	if err != nil {
		return nil, err
	}

	return &Service{
		Cfg:       env.Cfg,
		RedisCli:  env.RedisCli,
		MongoCli:  env.MongoCli,
		ctx:       context.Background(),
		RunPath:   runPath,
		ScRoot:    scRoot,
		PythonBin: py,
		Plugins:   idx,
	}, nil
}

// Start registers plugins/templates and consumes scan tasks from the scanner
// machinery queue until ctx is cancelled.
func (s *Service) Start(ctx context.Context) error {
	s = s.withContext(ctx)
	if err := RegisterPluginsAndTemplates(ctx, s.MongoCli, s.Plugins); err != nil {
		return err
	}

	concurrency := 8
	if v := getenvInt(common.ScannerConcurrencyEnv); v > 0 {
		concurrency = v
	}

	srv, err := taskq.NewServer(s.Cfg.Redis.URI, taskq.ScannerQueue)
	if err != nil {
		return err
	}
	err = srv.RegisterTasks(map[string]any{
		taskq.ScannerBaselineTask: s.taskHandler(func(svc *Service) scanTask { return &BaselineTask{svc: svc} }),
		taskq.ScannerLeakTask:     s.taskHandler(func(svc *Service) scanTask { return &LeakTask{svc: svc} }),
		taskq.ScannerWeakPwdTask:  s.taskHandler(func(svc *Service) scanTask { return &WeakPwdTask{svc: svc} }),
	})
	if err != nil {
		return err
	}

	worker := srv.NewWorker("ada_scanner_worker", concurrency)
	worker.SetErrorHandler(func(err error) { logger.Errorf("scanner task error: %v", err) })

	logger.Infof("scanner(scgo) starting machinery workers=%d queue=%s", concurrency, taskq.ScannerQueue)
	errCh := make(chan error, 1)
	worker.LaunchAsync(errCh)

	select {
	case <-ctx.Done():
		logger.Infof("scanner(scgo) context done, waiting workers...")
		worker.Quit()
		return nil
	case err := <-errCh:
		return err
	}
}

// taskHandler adapts a scanTask constructor to the machinery task signature.
// Every execution gets its own task instance bound to the task context, so
// parsed kwargs are never shared between concurrent runs.
func (s *Service) taskHandler(newTask func(*Service) scanTask) func(ctx context.Context, raw string) (string, error) {
	return func(ctx context.Context, raw string) (string, error) {
		payload, err := taskq.DecodeScannerPayload(raw)
		if err != nil {
			return "", err
		}
		kwargs := payload.Kwargs
		kwargs["_task_id"] = payload.TaskID

		t := newTask(s.withContext(ctx))
		if err := t.ParseKwargs(kwargs); err != nil {
			return "", err
		}
		res, err := t.RunTask()
		if err != nil {
			return "", err
		}
		switch v := res.(type) {
		case nil:
			return "", nil
		case string:
			return v, nil
		default:
			b, err := json.Marshal(v)
			if err != nil {
				return "", fmt.Errorf("encode task result: %w", err)
			}
			return string(b), nil
		}
	}
}

func getenvInt(key string) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return 0
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return 0
	}
	return i
}
