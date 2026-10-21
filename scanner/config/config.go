package config

import (
	"context"
	"fmt"
	"os"

	"ada/infra/mongo"
	"ada/infra/svcconfig"
	"ada/scanner/common"

	"github.com/redis/go-redis/v9"
)

// Shared configuration blocks (see infra/svcconfig).
type (
	LogCfg     = svcconfig.LogCfg
	RedisCfg   = svcconfig.RedisCfg
	MongodbCfg = svcconfig.MongodbCfg
)

type Config struct {
	ProjectName string     `yaml:"ProjectName"`
	Log         LogCfg     `yaml:"Log"`
	Redis       RedisCfg   `yaml:"Redis"`
	Mongodb     MongodbCfg `yaml:"Mongodb"`
}

type Env struct {
	Cfg      *Config
	RedisCli *redis.Client
	MongoCli mongo.DBAdaptor
	svcconfig.Ctx
}

const logModule = "scanner"

func Init(confPath string) (*Env, error) {
	var setting Config
	if err := svcconfig.LoadYAML(confPath, &setting); err != nil {
		return nil, err
	}

	// Allow env override (common in containerized deployments)
	if v := os.Getenv(common.ScannerEnvRedisURI); v != "" {
		setting.Redis.URI = v
	}
	if v := os.Getenv(common.ScannerEnvMongoURI); v != "" {
		setting.Mongodb.URI = v
	} else if v := os.Getenv(common.ScannerEnvMongoDBURI); v != "" {
		setting.Mongodb.URI = v
	}

	if setting.Redis.URI == "" {
		return nil, fmt.Errorf("empty Redis.URI in config: %s", confPath)
	}
	if setting.Mongodb.URI == "" {
		return nil, fmt.Errorf("empty Mongodb.URI in config: %s", confPath)
	}

	ctx := context.Background()
	redisCli, err := svcconfig.NewRedisClient(ctx, setting.Redis)
	if err != nil {
		return nil, err
	}

	mongoCli, err := svcconfig.NewMongoClient(ctx, setting.Mongodb)
	if err != nil {
		return nil, err
	}

	if err := svcconfig.InitLog(setting.Log, setting.ProjectName, logModule, mongoCli); err != nil {
		return nil, err
	}

	return &Env{Cfg: &setting, RedisCli: redisCli, MongoCli: mongoCli, Ctx: svcconfig.NewCtx(ctx)}, nil
}
