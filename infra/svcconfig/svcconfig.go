// Package svcconfig holds the configuration blocks and client constructors
// shared by every ADAegis service (apiserver, tasker, engine, scanner). Each
// service keeps its own Config struct for service-specific settings and embeds
// these types for the common ones.
package svcconfig

import (
	"context"
	"fmt"
	"os"
	"path"
	"time"

	"ada/infra/loghook"
	"ada/infra/mongo"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/natefinch/lumberjack"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/x/mongo/driver/connstring"
	"gopkg.in/yaml.v3"
)

// LogCfg configures logrus output.
type LogCfg struct {
	LogPath  string `yaml:"LogPath"`
	LogLevel string `yaml:"LogLevel"`
	IsStdOut bool   `yaml:"IsStdOut"`
}

// RedisCfg configures the Redis client (URI: redis://[user:]pass@host:port/db).
type RedisCfg struct {
	URI         string `yaml:"URI"`
	Active      int    `yaml:"Active"`
	Idle        int    `yaml:"Idle"`
	IdleTimeout int    `yaml:"IdleTimeout"`
}

// MongodbCfg configures the MongoDB client.
type MongodbCfg struct {
	URI       string `yaml:"URI"`
	PoolLimit uint64 `yaml:"PoolLimit"`
}

// ESCfg configures the optional Elasticsearch client.
type ESCfg struct {
	Enable    bool     `yaml:"Enable"`
	Addresses []string `yaml:"Addresses"`
	Username  string   `yaml:"Username"`
	Password  string   `yaml:"Password"`
}

const (
	redisDialTimeout = 15 * time.Second
	redisIOTimeout   = 10 * time.Second
	redisPoolSize    = 100

	logMaxSizeMB  = 30
	logMaxBackups = 2
	logMaxAgeDays = 60
)

// LoadYAML reads confPath and unmarshals it into out.
func LoadYAML(confPath string, out any) error {
	content, err := os.ReadFile(confPath)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(content, out); err != nil {
		return fmt.Errorf("parse %s: %w", confPath, err)
	}
	return nil
}

// InitLog configures the global logrus logger: level, destination (stdout or a
// rolling <logName>.log under cfg.LogPath) and the MongoDB hook that stores
// warnings/errors tagged with module. An empty LogLevel leaves logging at its
// defaults.
func InitLog(cfg LogCfg, logName, module string, mongoCli mongo.DBAdaptor) error {
	logrus.SetFormatter(&logrus.JSONFormatter{})
	if cfg.LogLevel == "" {
		return nil
	}

	lvl, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		return err
	}
	logrus.SetLevel(lvl)

	if cfg.IsStdOut {
		logrus.SetOutput(os.Stdout)
		logrus.SetFormatter(&logrus.TextFormatter{})
	} else if cfg.LogPath != "" {
		logrus.SetOutput(&lumberjack.Logger{
			Filename:   path.Join(cfg.LogPath, logName+".log"),
			MaxSize:    logMaxSizeMB,
			MaxBackups: logMaxBackups,
			MaxAge:     logMaxAgeDays,
			Compress:   false,
		})
	}

	logrus.SetReportCaller(true)
	if mongoCli != nil {
		logrus.AddHook(loghook.NewLogrusMongoHook(mongoCli, module))
	}
	return nil
}

// NewRedisClient connects to Redis described by cfg and verifies it with PING.
func NewRedisClient(ctx context.Context, cfg RedisCfg) (*redis.Client, error) {
	opt, err := redis.ParseURL(cfg.URI)
	if err != nil {
		return nil, fmt.Errorf("parse redis uri: %w", err)
	}

	opt.DialTimeout = redisDialTimeout
	opt.ReadTimeout = redisIOTimeout
	opt.WriteTimeout = redisIOTimeout
	opt.PoolSize = redisPoolSize

	rdb := redis.NewClient(opt)
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("ping redis: %w", err)
	}
	return rdb, nil
}

// NewMongoClient connects to the database named in cfg.URI.
func NewMongoClient(ctx context.Context, cfg MongodbCfg) (mongo.DBAdaptor, error) {
	cs, err := connstring.Parse(cfg.URI)
	if err != nil {
		return nil, fmt.Errorf("parse mongodb uri: %w", err)
	}

	mongoCli := mongo.NewMongoSession()
	if err := mongoCli.Connect(ctx, cfg.URI, cs.Database); err != nil {
		return nil, err
	}
	mongoCli.SetPoolLimit(cfg.PoolLimit)
	return mongoCli, nil
}

// NewElasticsearchClient returns nil, nil when cfg.Enable is false.
func NewElasticsearchClient(cfg ESCfg) (*elasticsearch.Client, error) {
	if !cfg.Enable {
		return nil, nil
	}
	return elasticsearch.NewClient(elasticsearch.Config{
		Addresses: cfg.Addresses,
		Username:  cfg.Username,
		Password:  cfg.Password,
	})
}

// Ctx carries the request context an Env is bound to. Services embed it in
// their Env so that MongoDB calls made through the Env propagate deadlines and
// cancellation of the originating request.
type Ctx struct {
	ctx context.Context
}

// NewCtx wraps ctx.
func NewCtx(ctx context.Context) Ctx {
	return Ctx{ctx: ctx}
}

// Context returns the bound context, or context.Background() when unset.
func (c Ctx) Context() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}

// With returns a copy bound to ctx (unchanged when ctx is nil).
func (c Ctx) With(ctx context.Context) Ctx {
	if ctx == nil {
		return c
	}
	return Ctx{ctx: ctx}
}
