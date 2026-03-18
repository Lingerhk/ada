package config

import (
	"ada/infra/loghook"
	"ada/infra/mongo"
	"context"
	"os"
	"path"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/natefinch/lumberjack"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
	"gopkg.in/yaml.v3"
)

type LogCfg struct {
	LogPath  string `yaml:"LogPath"`
	LogLevel string `yaml:"LogLevel"`
	IsStdOut bool   `yaml:"IsStdOut"`
}

type RedisCfg struct {
	URI         string `yaml:"URI"`
	Active      int    `yaml:"Active"`
	Idle        int    `yaml:"Idle"`
	IdleTimeout int    `yaml:"IdleTimeout"`
}

type MongodbCfg struct {
	URI       string `yaml:"URI"`
	PoolLimit uint64 `yaml:"PoolLimit"`
}

type ESCfg struct {
	Enable    bool     `yaml:"Enable"`
	Addresses []string `yaml:"Addresses"`
	Username  string   `yaml:"Username"`
	Password  string   `yaml:"Password"`
}

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
	ctx      context.Context
}

func InitLog(setting *Config, mongoCli mongo.DBAdaptor) error {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	if setting.Log.LogLevel == "" {
		return nil
	}

	lvl, err := logrus.ParseLevel(setting.Log.LogLevel)
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)

	if setting.Log.IsStdOut {
		logrus.SetOutput(os.Stdout)
		logrus.SetFormatter(&logrus.TextFormatter{})
	} else if setting.Log.LogPath != "" {
		logFile := path.Join(setting.Log.LogPath, setting.ProjectName+".log")
		logout := &lumberjack.Logger{
			Filename:   logFile,
			MaxSize:    30,    // 日志文件最大size, 单位是MB
			MaxBackups: 2,     // 最大过期日志保留的个数
			MaxAge:     60,    // 保留过期文件的最大时间间隔，单位是天
			Compress:   false, // 是否需要压缩滚动日志，使用的gzip压缩
		}
		logrus.SetOutput(logout)
	}

	logrus.SetReportCaller(true)
	// Use MongoDB hook instead of Redis
	hook := loghook.NewLogrusMongoHook(mongoCli, "engine")
	logrus.AddHook(hook)
	return nil
}

func InitRedisClient(setting *Config) (*redis.Client, error) {
	opt, err := redis.ParseURL(setting.Redis.URI)
	if err != nil {
		return nil, err
	}

	opt.DialTimeout = 15 * time.Second
	opt.ReadTimeout = 10 * time.Second
	opt.WriteTimeout = 10 * time.Second
	opt.PoolSize = 100

	rdb := redis.NewClient(opt)
	_, err = rdb.Ping(context.Background()).Result()
	if err != nil {
		return nil, err
	}

	return rdb, err
}

func InitMongoClient(setting *Config) (mongo.DBAdaptor, error) {
	mongoCli := mongo.NewMongoSession()

	cs, err := connstring.Parse(setting.Mongodb.URI)
	if err != nil {
		return nil, err
	}

	err = mongoCli.Connect(context.Background(), setting.Mongodb.URI, cs.Database)
	if err != nil {
		return nil, err
	}

	mongoCli.SetPoolLimit(setting.Mongodb.PoolLimit)

	return mongoCli, nil
}

func InitElasticsearch(setting *Config) (*elasticsearch.Client, error) {
	if !setting.ES.Enable {
		return nil, nil
	}

	cfg := elasticsearch.Config{
		Addresses: setting.ES.Addresses,
		Username:  setting.ES.Username,
		Password:  setting.ES.Password,
	}
	esCli, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return esCli, nil
}

func Init(confPath string) (*Env, error) {
	content, err := os.ReadFile(confPath)
	if err != nil {
		return nil, err
	}

	var setting Config
	err = yaml.Unmarshal(content, &setting)
	if err != nil {
		return nil, err
	}

	redisCli, err := InitRedisClient(&setting)
	if err != nil {
		return nil, err
	}

	mongoCli, err := InitMongoClient(&setting)
	if err != nil {
		return nil, err
	}

	err = InitLog(&setting, mongoCli)
	if err != nil {
		return nil, err
	}

	esCli, err := InitElasticsearch(&setting)
	if err != nil {
		return nil, err
	}

	return &Env{Cfg: &setting, RedisCli: redisCli, MongoCli: mongoCli, ESCli: esCli, ctx: context.Background()}, nil
}
