package gocelery

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCeleryBroker is celery broker for redis
type RedisCeleryBroker struct {
	ctx       context.Context
	redisCli  *redis.Client
	QueueName string
}

// NewRedisBroker creates new RedisCeleryBroker with given redis connection pool
func NewRedisBroker(ctx context.Context, conn *redis.Client) *RedisCeleryBroker {
	defaultQueue := "ada:scanner:task_queue"

	return &RedisCeleryBroker{
		ctx:       ctx,
		redisCli:  conn,
		QueueName: defaultQueue,
	}
}

// NewRedisCeleryBroker creates new RedisCeleryBroker based on given uri
//
// Deprecated: NewRedisCeleryBroker exists for historical compatibility
// and should not be used. Use NewRedisBroker instead to create new RedisCeleryBroker.
func NewRedisCeleryBroker(ctx context.Context, uri, queueName string) *RedisCeleryBroker {
	return &RedisCeleryBroker{
		ctx:       ctx,
		redisCli:  NewRedisClient(ctx, uri),
		QueueName: queueName,
	}
}

// SendCeleryMessage sends CeleryMessage to redis queue
func (cb *RedisCeleryBroker) SendCeleryMessage(message *CeleryMessage) error {
	jsonBytes, err := json.Marshal(message)
	if err != nil {
		return err
	}
	err = cb.redisCli.LPush(cb.ctx, cb.QueueName, jsonBytes).Err()
	if err != nil {
		return err
	}
	return nil
}

// GetCeleryMessage retrieves celery message from redis queue
func (cb *RedisCeleryBroker) GetCeleryMessage() (*CeleryMessage, error) {
	// Use a real second value; go-redis treats small durations (like 1ns) as invalid.
	messageInfo, err := cb.redisCli.BRPop(cb.ctx, 1*time.Second, cb.QueueName).Result()
	if err != nil {
		return nil, err
	}
	if messageInfo == nil || len(messageInfo) < 2 {
		return nil, fmt.Errorf("null message received from redis")
	}

	if messageInfo[0] != cb.QueueName {
		return nil, fmt.Errorf("not a celery message: %v", messageInfo[0])
	}

	var message CeleryMessage
	if err := json.Unmarshal([]byte(messageInfo[1]), &message); err != nil {
		return nil, err
	}
	return &message, nil
}

// GetTaskMessage retrieves task message from redis queue
func (cb *RedisCeleryBroker) GetTaskMessage() (*TaskMessage, error) {
	celeryMessage, err := cb.GetCeleryMessage()
	if err != nil {
		return nil, err
	}
	return celeryMessage.GetTaskMessage(), nil
}

func NewRedisClient(ctx context.Context, uri string) *redis.Client {
	opt, err := redis.ParseURL(uri)
	if err != nil {
		panic(err)
	}

	opt.DialTimeout = 15 * time.Second
	opt.ReadTimeout = 10 * time.Second
	opt.WriteTimeout = 10 * time.Second
	opt.PoolSize = 100

	redisClient := redis.NewClient(opt)
	_, err = redisClient.Ping(ctx).Result()
	if err != nil {
		panic(err)
	}

	return redisClient
}
