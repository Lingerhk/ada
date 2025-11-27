package loghook

import (
	"ada/infra/mongo"
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	defaultRedisQueueExpire = time.Hour * 12 // expire 12h
	defaultMaxLogsSize      = 1000
	defaultRedisQueueName   = "ada:logs_queue"
	defaultMongoCollName    = "tb_system_logs"
)

// ==================== Redis Hook ====================

// LogrusRedis delivers logs to a Redis List
type LogrusRedis struct {
	ctx         context.Context
	client      *redis.Client
	key         string
	rangeCursor int64
	len         int64
	Expire      time.Duration
	formatter   *logrus.TextFormatter
}

// Fire adds logrus entry into redis list
func (r *LogrusRedis) Fire(entry *logrus.Entry) error {
	body, err := r.formatter.Format(entry)
	if err != nil {
		return err
	}

	// if queue too long, we need delete some old logs first.
	if r.client.LLen(r.ctx, r.key).Val() > defaultMaxLogsSize {
		r.client.LTrim(r.ctx, r.key, 100, -1)
	}

	err = r.client.LPush(r.ctx, r.key, body).Err()
	if err != nil {
		return err
	}

	return r.client.Expire(r.ctx, r.key, r.Expire).Err()
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
	formatter  *logrus.JSONFormatter
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
	total, err := h.mongoCli.FindCount(h.collection, bson.M{})
	if err != nil {
		return err
	}

	if total > defaultMaxLogsSize {
		// Find the oldest 100 logs by sorting by time ascending
		var oldLogs []SystemLog
		err = h.mongoCli.FindSortByLimitAndSkip(
			h.collection,
			bson.M{},
			bson.M{"time": 1}, // Sort ascending (oldest first)
			&oldLogs,
			100, // Get 100 oldest
			0,
		)
		if err == nil && len(oldLogs) > 0 {
			// Extract timestamp of the 100th oldest log
			oldestTime := oldLogs[len(oldLogs)-1].Time
			// Delete all logs older than or equal to the 100th oldest log
			h.mongoCli.Remove(h.collection, bson.M{"time": bson.M{"$lte": oldestTime}}, true)
		}
	}

	// Insert into MongoDB using DBAdaptor
	err = h.mongoCli.Insert(h.collection, logDoc)
	if err != nil {
		// Log insertion error but don't propagate to avoid logging loops
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
	fieldMap := logrus.FieldMap{
		"module": module,
	}

	hook := &LogrusMongoHook{
		ctx:        context.Background(),
		mongoCli:   mongoCli,
		collection: defaultMongoCollName,
		module:     module,
		formatter:  &logrus.JSONFormatter{FieldMap: fieldMap},
	}

	return hook
}
