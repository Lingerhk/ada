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

type TaskSrvCfg struct {
	GrpcAddr   string `yaml:"GrpcAddr"`
	HttpAddr   string `yaml:"HttpAddr"`
	SyslogAddr string `yaml:"SyslogAddr"`
}

type Config struct {
	ProjectName string     `yaml:"ProjectName"`
	Log         LogCfg     `yaml:"Log"`
	TaskSrv     TaskSrvCfg `yaml:"TaskSrv"`
	Redis       RedisCfg   `yaml:"Redis"`
	Mongodb     MongodbCfg `yaml:"Mongodb"`
	ES          ESCfg      `yaml:"ES"`
}

type Env struct {
	Cfg      *Config
	RedisCli *redis.Client
	MongoCli mongo.DBAdaptor
	EsCli    *elasticsearch.Client
	svcconfig.Ctx
}

// Init loads confPath and connects the clients. moduleName ("server" or
// "worker") distinguishes the two tasker processes in log file names and in
// the MongoDB log hook.
func Init(confPath, moduleName string) (*Env, error) {
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

	if err := svcconfig.InitLog(setting.Log, setting.ProjectName+"_"+moduleName, "task_"+moduleName, mongoCli); err != nil {
		return nil, err
	}

	esCli, err := svcconfig.NewElasticsearchClient(setting.ES)
	if err != nil {
		return nil, err
	}

	return &Env{Cfg: &setting, RedisCli: redisCli, MongoCli: mongoCli, EsCli: esCli, Ctx: svcconfig.NewCtx(ctx)}, nil
}
