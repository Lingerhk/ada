package logrusredis

import (
	"context"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"time"
)

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
	if r.client.LLen(r.ctx, r.key).Val() > 10000 {
		r.client.LTrim(r.ctx, r.key, 1000, -1)
	}

	err = r.client.LPush(r.ctx, r.key, body).Err()
	if err != nil {
		return err
	}

	return r.client.Expire(r.ctx, r.key, r.Expire).Err()
}

// Levels returns the available logging levels.
func (r *LogrusRedis) Levels() []logrus.Level {
	//return logrus.AllLevels

	return []logrus.Level{
		logrus.WarnLevel,
		logrus.ErrorLevel,
		logrus.FatalLevel,
		logrus.PanicLevel,
	}
}

// NewLogrusRedis creates LogrusRedis instance
func NewLogrusRedis(client *redis.Client, key string) *LogrusRedis {
	return &LogrusRedis{
		ctx:       context.Background(),
		client:    client,
		key:       key,
		Expire:    time.Hour * 6, // expire 6h
		formatter: &logrus.TextFormatter{DisableColors: true},
	}
}
