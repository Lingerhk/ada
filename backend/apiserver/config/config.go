package config

import (
	logrusredis "ada/infra/loghook"
	"ada/infra/mongo"
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/natefinch/lumberjack"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type LogCfg struct {
	LogPath  string `yaml:"LogPath"`
	LogLevel string `yaml:"LogLevel"`
	IsStdOut bool   `yaml:"IsStdOut"`
}

type BindSrvCfg struct {
	GrpcAddr string `yaml:"GrpcAddr"`
	HttpAddr string `yaml:"HttpAddr"`
	TaskAddr string `yaml:"TaskAddr"`
}

type RedisCfg struct {
	URI         string        `yaml:"URI"`
	Active      int           `yaml:"Active"`
	Idle        int           `yaml:"Idle"`
	IdleTimeout time.Duration `yaml:"IdleTimeout"`
}

type MongodbCfg struct {
	Host      string `yaml:"Host"`
	User      string `yaml:"User"`
	Passwd    string `yaml:"Passwd"`
	DbName    string `yaml:"DbName"`
	PoolLimit uint64 `yaml:"PoolLimit"`
}

type Config struct {
	ProjectName string     `yaml:"ProjectName"`
	Log         LogCfg     `yaml:"Log"`
	BindSrv     BindSrvCfg `yaml:"BindSrv"`
	Redis       RedisCfg   `yaml:"Redis"`
	Mongodb     MongodbCfg `yaml:"Mongodb"`
}

type Env struct {
	Cfg      *Config
	RedisCli *redis.Client
	MongoCli mongo.DBAdaptor
}

func InitLog(setting *Config, redisCli *redis.Client) error {
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
		if err == nil {
			logout := &lumberjack.Logger{
				Filename:   logFile,
				MaxSize:    30,    // 日志文件最大size, 单位是MB
				MaxBackups: 2,     // 最大过期日志保留的个数
				MaxAge:     60,    // 保留过期文件的最大时间间隔，单位是天
				Compress:   false, // 是否需要压缩滚动日志，使用的gzip压缩
			}
			logrus.SetOutput(logout)
		}
	}

	logrus.SetReportCaller(true)
	hook := logrusredis.NewLogrusRedis(redisCli, "ada:logs_queue:apiserver")
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
	MongoURL := fmt.Sprintf("mongodb://%s:%s@%s/%s?authSource=%s",
		setting.Mongodb.User, setting.Mongodb.Passwd, setting.Mongodb.Host, setting.Mongodb.DbName, setting.Mongodb.DbName)

	err := mongoCli.Connect(MongoURL, setting.Mongodb.DbName)
	if err != nil {
		return nil, err
	}

	mongoCli.SetPoolLimit(setting.Mongodb.PoolLimit)

	return mongoCli, nil
}

func Init(confPath string) (*Env, error) {
	content, err := os.ReadFile(confPath)
	if err != nil {
		panic(err)
	}

	var setting Config
	err = yaml.Unmarshal(content, &setting)
	if err != nil {
		panic(err)
	}

	redisCli, err := InitRedisClient(&setting)
	if err != nil {
		return nil, err
	}

	err = InitLog(&setting, redisCli)
	if err != nil {
		return nil, err
	}

	mongoCli, err := InitMongoClient(&setting)
	if err != nil {
		return nil, err
	}

	return &Env{&setting, redisCli, mongoCli}, nil
}
