package gocelery

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// RedisCeleryBackend is celery backend for redis
type RedisCeleryBackend struct {
	ctx         context.Context
	redisClient *redis.Client
}

// NewRedisBackend creates new RedisCeleryBackend with given redis pool.
// RedisCeleryBackend can be initialized manually as well.
func NewRedisBackend(ctx context.Context, rdxCli *redis.Client) *RedisCeleryBackend {
	return &RedisCeleryBackend{
		ctx:         ctx,
		redisClient: rdxCli,
	}
}

// NewRedisCeleryBackend creates new RedisCeleryBackend
//
// Deprecated: NewRedisCeleryBackend exists for historical compatibility
// and should not be used. Pool should be initialized outside of gocelery package.
func NewRedisCeleryBackend(ctx context.Context, uri string) *RedisCeleryBackend {
	redisClient, err := NewRedisClientE(ctx, uri)
	if err != nil {
		return nil
	}
	return &RedisCeleryBackend{
		ctx:         ctx,
		redisClient: redisClient,
	}
}

// GetResult queries redis backend to get asynchronous result
func (cb *RedisCeleryBackend) GetResult(taskID string) (*ResultMessage, error) {
	val, err := cb.redisClient.Get(cb.ctx, fmt.Sprintf("celery-task-meta-%s", taskID)).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, fmt.Errorf("result not available")
		}
		return nil, err
	}
	if len(val) == 0 {
		return nil, fmt.Errorf("empty result found")
	}
	var resultMessage ResultMessage
	err = json.Unmarshal(val, &resultMessage)
	if err != nil {
		return nil, err
	}
	return &resultMessage, nil
}

// SetResult pushes result back into redis backend
func (cb *RedisCeleryBackend) SetResult(taskID string, result *ResultMessage) error {
	resBytes, err := json.Marshal(result)
	if err != nil {
		return err
	}

	return cb.redisClient.SetEx(cb.ctx, fmt.Sprintf("celery-task-meta-%s", taskID), resBytes, 60*60).Err()
}
