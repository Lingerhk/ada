package config

import (
	"context"

	"ada/infra/mongo"
	"ada/infra/svcconfig"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/redis/go-redis/v9"
)

// Shared configuration blocks (see infra/svcconfig).
type (
	LogCfg     = svcconfig.LogCfg
	RedisCfg   = svcconfig.RedisCfg
	MongodbCfg = svcconfig.MongodbCfg
	ESCfg      = svcconfig.ESCfg
)

type Config struct {
	ProjectName string     `yaml:"ProjectName"`
	Log         LogCfg     `yaml:"Log"`
	Redis       RedisCfg   `yaml:"Redis"`
	Mongodb     MongodbCfg `yaml:"Mongodb"`
	ES          ESCfg      `yaml:"ES"`
}

type Env struct {
	Cfg      *Config
	RedisCli *redis.Client
	MongoCli mongo.DBAdaptor
	ESCli    *elasticsearch.Client
	svcconfig.Ctx
}

const logModule = "engine"

func Init(confPath string) (*Env, error) {
	var setting Config
	if err := svcconfig.LoadYAML(confPath, &setting); err != nil {
		return nil, err
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

	esCli, err := svcconfig.NewElasticsearchClient(setting.ES)
	if err != nil {
		return nil, err
	}

	return &Env{Cfg: &setting, RedisCli: redisCli, MongoCli: mongoCli, ESCli: esCli, Ctx: svcconfig.NewCtx(ctx)}, nil
}
