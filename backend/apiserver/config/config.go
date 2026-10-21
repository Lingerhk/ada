package config

import (
	"context"

	"ada/infra/mongo"
	"ada/infra/svcconfig"

	"github.com/redis/go-redis/v9"
)

// Shared configuration blocks (see infra/svcconfig).
type (
	LogCfg     = svcconfig.LogCfg
	RedisCfg   = svcconfig.RedisCfg
	MongodbCfg = svcconfig.MongodbCfg
)

type BindSrvCfg struct {
	GrpcAddr string `yaml:"GrpcAddr"`
	HttpAddr string `yaml:"HttpAddr"`
	TaskAddr string `yaml:"TaskAddr"`
}

type KibanaCfg struct {
	Address  string `yaml:"Address"`  // Kibana Addr
	Username string `yaml:"Username"` // Kibana username for auto-login
	Password string `yaml:"Password"` // Kibana password for auto-login
}

type Config struct {
	ProjectName string     `yaml:"ProjectName"`
	Log         LogCfg     `yaml:"Log"`
	BindSrv     BindSrvCfg `yaml:"BindSrv"`
	Redis       RedisCfg   `yaml:"Redis"`
	Mongodb     MongodbCfg `yaml:"Mongodb"`
	Kibana      KibanaCfg  `yaml:"Kibana"`
}

type Env struct {
	Cfg      *Config
	RedisCli *redis.Client
	MongoCli mongo.DBAdaptor
	svcconfig.Ctx
}

const logModule = "apiserver"

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

	return &Env{Cfg: &setting, RedisCli: redisCli, MongoCli: mongoCli, Ctx: svcconfig.NewCtx(ctx)}, nil
}
