package config

import (
	logrusredis "ada/infra/loghook"
	"ada/infra/mongo"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
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

type TaskSrvCfg struct {
	GrpcAddr   string `yaml:"GrpcAddr"`
	HttpAddr   string `yaml:"HttpAddr"`
	SyslogAddr string `yaml:"SyslogAddr"`
}

type RedisCfg struct {
	URI         string        `yaml:"URI"`
	Active      int           `yaml:"Active"`
	Idle        int           `yaml:"Idle"`
	IdleTimeout time.Duration `yaml:"IdleTimeout"`
	AddrTmp     string
}

type MongodbCfg struct {
	Host      string `yaml:"Host"`
	User      string `yaml:"User"`
	Passwd    string `yaml:"Passwd"`
	DbName    string `yaml:"DbName"`
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
}

func InitLog(setting *Config, redisCli *redis.Client, moduleName string) error {
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
		logName := fmt.Sprintf("%s_%s.log", setting.ProjectName, moduleName)
		logFile := path.Join(setting.Log.LogPath, logName)
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
	hook := logrusredis.NewLogrusRedis(redisCli, "ada:logs_queue:task_"+moduleName)
	logrus.AddHook(hook)
	return nil
}

func InitRedisClient(setting *Config) (*redis.Client, error) {
	opt, err := redis.ParseURL(setting.Redis.URI)
	if err != nil {
		return nil, err
	}

	setting.Redis.AddrTmp = fmt.Sprintf("%s@%s", opt.Password, opt.Addr)

	opt.DialTimeout = 15 * time.Second
	opt.ReadTimeout = 15 * time.Second
	opt.WriteTimeout = 15 * time.Second
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
		panic(err)
	}
	return esCli, nil
}

func Init(confPath, moduleName string) (*Env, error) {
	content, err := ioutil.ReadFile(confPath)
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

	err = InitLog(&setting, redisCli, moduleName)
	if err != nil {
		return nil, err
	}

	mongoCli, err := InitMongoClient(&setting)
	if err != nil {
		return nil, err
	}

	esCli, err := InitElasticsearch(&setting)
	if err != nil {
		return nil, err
	}

	return &Env{&setting, redisCli, mongoCli, esCli}, nil
}
