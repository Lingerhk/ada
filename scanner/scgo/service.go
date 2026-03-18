package scgo

import (
	"ada/infra/gocelery"
	"ada/infra/mongo"
	"ada/scanner/common"
	"ada/scanner/config"
	"context"
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
	RunPath   string // e.g. /var/lib/scada
	ScRoot    string // e.g. /var/lib/scada/.sc
	PythonBin string
	Plugins   *PluginIndex
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
		RunPath:   runPath,
		ScRoot:    scRoot,
		PythonBin: py,
		Plugins:   idx,
	}, nil
}

func (s *Service) Start(ctx context.Context) error {
	s = s.withContext(ctx)
	if err := RegisterPluginsAndTemplates(s.MongoCli, s.Plugins); err != nil {
		return err
	}

	concurrency := 8
	if v := getenvInt(common.ScannerConcurrencyEnv); v > 0 {
		concurrency = v
	}

	broker := gocelery.NewRedisBroker(ctx, s.RedisCli)
	backend := gocelery.NewRedisBackend(ctx, s.RedisCli)
	cc, err := gocelery.NewCeleryClient(broker, backend, concurrency)
	if err != nil {
		return err
	}

	// Register factory tasks to avoid data races.
	cc.Register("tasks.baseline.execute_baseline", func() gocelery.CeleryTask { return &BaselineTask{svc: s.withContext(ctx)} })
	cc.Register("tasks.leak.execute_leak", func() gocelery.CeleryTask { return &LeakTask{svc: s.withContext(ctx)} })
	cc.Register("tasks.weakpwd.execute_weakpwd", func() gocelery.CeleryTask { return &WeakPwdTask{svc: s.withContext(ctx)} })

	logger.Infof("scanner(scgo) starting celery workers=%d", concurrency)
	cc.StartWorkerWithContext(ctx)
	<-ctx.Done()
	logger.Infof("scanner(scgo) context done, waiting workers...")
	cc.WaitForStopWorker()
	return nil
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
