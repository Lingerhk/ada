package loghook

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

type fakeRedisListClient struct {
	mu     sync.Mutex
	lists  map[string][]string
	ttl    map[string]time.Duration
	expiry map[string]time.Time
}

func newFakeRedisListClient() *fakeRedisListClient {
	return &fakeRedisListClient{
		lists:  make(map[string][]string),
		ttl:    make(map[string]time.Duration),
		expiry: make(map[string]time.Time),
	}
}

func (f *fakeRedisListClient) LLen(_ context.Context, key string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.lists[key])), nil
}

func (f *fakeRedisListClient) LTrim(_ context.Context, key string, start, stop int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	list := f.lists[key]
	if len(list) == 0 {
		return nil
	}

	if start < 0 {
		start = 0
	}
	if stop < 0 {
		stop = int64(len(list) - 1)
	}
	if start >= int64(len(list)) {
		f.lists[key] = nil
		return nil
	}
	if stop >= int64(len(list)) {
		stop = int64(len(list) - 1)
	}
	if start > stop {
		f.lists[key] = nil
		return nil
	}

	f.lists[key] = append([]string(nil), list[start:stop+1]...)
	return nil
}

func (f *fakeRedisListClient) LPush(_ context.Context, key string, values ...string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	list := f.lists[key]
	for _, value := range values {
		list = append([]string{value}, list...)
	}
	f.lists[key] = list
	return nil
}

func (f *fakeRedisListClient) Expire(_ context.Context, key string, expiration time.Duration) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ttl[key] = expiration
	f.expiry[key] = time.Now().Add(expiration)
	return nil
}

func (f *fakeRedisListClient) clear(key string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.lists, key)
	delete(f.ttl, key)
	delete(f.expiry, key)
}

func (f *fakeRedisListClient) index(key string, idx int) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if idx < 0 || idx >= len(f.lists[key]) {
		return ""
	}
	return f.lists[key][idx]
}

func (f *fakeRedisListClient) ttlFor(key string) time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.ttl[key]
}

func TestLogrusRedisHook(t *testing.T) {
	client := newFakeRedisListClient()
	testKey := "ada:logs_queue:test_redis_hook"

	logger := logrus.New()
	logger.SetReportCaller(true)

	hook := newLogrusRedisWithClient(client, testKey)
	logger.AddHook(hook)

	t.Run("Test log levels", func(t *testing.T) {
		client.clear(testKey)

		logger.Info("This is info - should not be saved")
		logger.Debug("This is debug - should not be saved")
		logger.Warn("This is warning - should be saved")
		logger.Error("This is error - should be saved")

		count, err := client.LLen(context.Background(), testKey)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count, "Should have 2 logs (warn + error)")
	})

	t.Run("Test log content", func(t *testing.T) {
		client.clear(testKey)

		logger.Error("Test error message")

		logLine := client.index(testKey, 0)
		assert.NotEmpty(t, logLine)
		assert.Contains(t, logLine, "level=error")
		assert.Contains(t, logLine, "Test error message")
	})

	t.Run("Test Levels method", func(t *testing.T) {
		levels := hook.Levels()
		assert.Equal(t, 4, len(levels))
		assert.Contains(t, levels, logrus.WarnLevel)
		assert.Contains(t, levels, logrus.ErrorLevel)
		assert.Contains(t, levels, logrus.FatalLevel)
		assert.Contains(t, levels, logrus.PanicLevel)
		assert.NotContains(t, levels, logrus.InfoLevel)
		assert.NotContains(t, levels, logrus.DebugLevel)
	})

	t.Run("Test queue trimming", func(t *testing.T) {
		client.clear(testKey)

		for i := 0; i < defaultMaxLogsSize; i++ {
			assert.NoError(t, client.LPush(context.Background(), testKey, "dummy log"))
		}

		logger.Error("New log after limit")

		count, err := client.LLen(context.Background(), testKey)
		assert.NoError(t, err)
		expected := int64(defaultMaxLogsSize - defaultTrimBatchSize + 1)
		assert.Equal(t, expected, count, "Queue should trim a batch before pushing the new log")
		assert.Contains(t, client.index(testKey, 0), "New log after limit")
	})

	t.Run("Test expire functionality", func(t *testing.T) {
		client.clear(testKey)

		logger.Warn("Test expire")

		assert.Equal(t, defaultRedisQueueExpire, client.ttlFor(testKey))
	})

	t.Run("Test log format", func(t *testing.T) {
		client.clear(testKey)

		logger.WithField("user", "test_user").Error("Test with fields")

		logLine := client.index(testKey, 0)
		assert.Contains(t, logLine, "level=error")
		assert.Contains(t, logLine, "msg=\"Test with fields\"")
		assert.Contains(t, logLine, "user=test_user")
		assert.False(t, strings.Contains(logLine, "\x1b["), "Log should not contain color codes")
	})
}
