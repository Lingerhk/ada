package loghook

import (
	"ada/infra/mongo"
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	defaultRedisQueueExpire = time.Hour * 12 // expire 12h
	defaultMaxLogsSize      = 1000
	defaultTrimBatchSize    = 100
	defaultRedisQueueName   = "ada:logs_queue"
	defaultMongoCollName    = "tb_system_logs"
)

type redisListClient interface {
	LLen(ctx context.Context, key string) (int64, error)
	LTrim(ctx context.Context, key string, start, stop int64) error
	LPush(ctx context.Context, key string, values ...string) error
	Expire(ctx context.Context, key string, expiration time.Duration) error
}

type redisClientAdapter struct {
	client *redis.Client
}

func (a redisClientAdapter) LLen(ctx context.Context, key string) (int64, error) {
	return a.client.LLen(ctx, key).Result()
}

func (a redisClientAdapter) LTrim(ctx context.Context, key string, start, stop int64) error {
	return a.client.LTrim(ctx, key, start, stop).Err()
}

func (a redisClientAdapter) LPush(ctx context.Context, key string, values ...string) error {
	parts := make([]any, len(values))
	for i, value := range values {
		parts[i] = value
	}
	return a.client.LPush(ctx, key, parts...).Err()
}

func (a redisClientAdapter) Expire(ctx context.Context, key string, expiration time.Duration) error {
	return a.client.Expire(ctx, key, expiration).Err()
}

// ==================== Redis Hook ====================

// LogrusRedis delivers logs to a Redis List
type LogrusRedis struct {
	ctx       context.Context
	client    redisListClient
	key       string
	Expire    time.Duration
	formatter *logrus.TextFormatter
}

// Fire adds logrus entry into redis list
func (r *LogrusRedis) Fire(entry *logrus.Entry) error {
	body, err := r.formatter.Format(entry)
	if err != nil {
		return err
	}

	// if queue too long, we need delete some old logs first.
	queueLen, err := r.client.LLen(r.ctx, r.key)
	if err != nil {
		return err
	}
	if queueLen >= defaultMaxLogsSize {
		if err := r.client.LTrim(r.ctx, r.key, defaultTrimBatchSize, -1); err != nil {
			return err
		}
	}

	err = r.client.LPush(r.ctx, r.key, string(body))
	if err != nil {
		return err
	}

	return r.client.Expire(r.ctx, r.key, r.Expire)
}

// Levels returns the available logging levels.
func (r *LogrusRedis) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.WarnLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}

// NewLogrusRedis creates LogrusRedis instance
func NewLogrusRedis(client *redis.Client, key string) *LogrusRedis {
	return newLogrusRedisWithClient(redisClientAdapter{client: client}, key)
}

func newLogrusRedisWithClient(client redisListClient, key string) *LogrusRedis {
	if key == "" {
		key = defaultRedisQueueName
	}
	return &LogrusRedis{
		ctx:       context.Background(),
		client:    client,
		key:       key,
		Expire:    defaultRedisQueueExpire,
		formatter: &logrus.TextFormatter{DisableColors: true},
	}
}

// ==================== MongoDB Hook ====================

// LogrusMongoHook delivers logs to MongoDB collection
type LogrusMongoHook struct {
	ctx        context.Context
	mongoCli   mongo.DBAdaptor
	collection string
	module     string
}

// SystemLog represents the log document structure in MongoDB
type SystemLog struct {
	Time   time.Time `bson:"time"`
	Level  string    `bson:"level"`
	Module string    `bson:"module"`
	Msg    string    `bson:"msg"`
	Func   string    `bson:"func"`
	File   string    `bson:"file"`
}

// Fire adds logrus entry into MongoDB collection
func (h *LogrusMongoHook) Fire(entry *logrus.Entry) error {
	// Create log document from logrus entry
	logDoc := SystemLog{
		Time:   entry.Time,
		Level:  entry.Level.String(),
		Module: h.module,
		Msg:    entry.Message,
	}

	// Add caller information if available
	if entry.HasCaller() {
		logDoc.Func = entry.Caller.Function
		logDoc.File = fmt.Sprintf("%s:%d", entry.Caller.File, entry.Caller.Line)
	}

	// Check if logs collection is too large
	// If total > defaultMaxLogsSize (1000), delete the oldest 100 logs
	total, err := h.mongoCli.FindCount(h.ctx, h.collection, bson.M{})
	if err != nil {
		return err
	}

	if total >= defaultMaxLogsSize {
		// Find the oldest logs by sorting by time ascending.
		var oldLogs []SystemLog
		err = h.mongoCli.FindSortByLimitAndSkip(
			h.ctx,
			h.collection,
			bson.M{},
			bson.M{"time": 1},
			&oldLogs,
			defaultTrimBatchSize,
			0,
		)
		if err == nil && len(oldLogs) > 0 {
			sort.Slice(oldLogs, func(i, j int) bool {
				return oldLogs[i].Time.Before(oldLogs[j].Time)
			})
			oldestTime := oldLogs[len(oldLogs)-1].Time
			if err := h.mongoCli.Remove(h.ctx, h.collection, bson.M{"time": bson.M{"$lte": oldestTime}}, true); err != nil {
				return err
			}
		}
	}

	// Insert into MongoDB using DBAdaptor
	err = h.mongoCli.Insert(h.ctx, h.collection, logDoc)
	if err != nil {
		return err
	}

	return nil
}

// Levels returns the available logging levels
// Only hook warn, error, fatal, and panic levels
func (h *LogrusMongoHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.WarnLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}

// NewLogrusMongoHook creates a new LogrusMongoHook instance
func NewLogrusMongoHook(mongoCli mongo.DBAdaptor, module string) *LogrusMongoHook {
	return NewLogrusMongoHookWithCollection(mongoCli, module, defaultMongoCollName)
}

func NewLogrusMongoHookWithCollection(mongoCli mongo.DBAdaptor, module, collection string) *LogrusMongoHook {
	if collection == "" {
		collection = defaultMongoCollName
	}
	hook := &LogrusMongoHook{
		ctx:        context.Background(),
		mongoCli:   mongoCli,
		collection: collection,
		module:     module,
	}

	return hook
}
