package loghook

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// TestLogrusRedisHook tests the Redis hook functionality
func TestLogrusRedisHook(t *testing.T) {
	// Connect to Redis at 192.168.7.2 with credentials from apiserver.yaml
	ctx := context.Background()
	redisURI := "redis://:1pa2YgE3jfTbVVpn06CN@192.168.7.2:6379/0"

	opt, err := redis.ParseURL(redisURI)
	if err != nil {
		t.Skipf("Failed to parse Redis URI, skipping test: %v", err)
		return
	}

	client := redis.NewClient(opt)
	defer client.Close()

	// Ping Redis to verify connection
	err = client.Ping(ctx).Err()
	if err != nil {
		t.Skipf("Redis not reachable, skipping test: %v", err)
		return
	}

	// Use test queue
	testKey := "ada:logs_queue:test_redis_hook"

	// Clean up test queue before and after test
	client.Del(ctx, testKey)
	defer client.Del(ctx, testKey)

	// Create logger with Redis hook
	logger := logrus.New()
	logger.SetReportCaller(true)

	hook := NewLogrusRedis(client, testKey)
	logger.AddHook(hook)

	// Test different log levels
	t.Run("Test log levels", func(t *testing.T) {
		logger.Info("This is info - should not be saved")
		logger.Debug("This is debug - should not be saved")
		logger.Warn("This is warning - should be saved")
		logger.Error("This is error - should be saved")

		// Wait a bit for async operations
		time.Sleep(100 * time.Millisecond)

		// Count logs in queue
		count := client.LLen(ctx, testKey).Val()
		assert.Equal(t, int64(2), count, "Should have 2 logs (warn + error)")
	})

	t.Run("Test log content", func(t *testing.T) {
		// Clear queue
		client.Del(ctx, testKey)

		// Log a specific message
		logger.Error("Test error message")
		time.Sleep(100 * time.Millisecond)

		// Get the log entry (LPUSH adds to head, so get index 0)
		logLine := client.LIndex(ctx, testKey, 0).Val()
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

	t.Run("Test queue trimming at 10000 logs", func(t *testing.T) {
		// Clear queue
		client.Del(ctx, testKey)

		// Simulate 10001 logs already in queue
		// Add dummy logs to reach 10001
		for i := 0; i < 10001; i++ {
			client.LPush(ctx, testKey, "dummy log")
		}

		// Verify we have 10001 logs
		count := client.LLen(ctx, testKey).Val()
		assert.Equal(t, int64(10001), count)

		// Add one more log through the hook
		// This should trigger trim (keeps from index 1000 to -1, then adds 1 new)
		logger.Error("New log after limit")
		time.Sleep(100 * time.Millisecond)

		// LTRIM keeps from index 1000 to end, which is 9001 logs (indices 1000-10000)
		// Then LPUSH adds 1 new log at head = 9002 total
		count = client.LLen(ctx, testKey).Val()
		assert.Equal(t, int64(9002), count, "Queue should keep from index 1000 to end + 1 new log")

		// Verify the new log is at the head
		logLine := client.LIndex(ctx, testKey, 0).Val()
		assert.Contains(t, logLine, "New log after limit")
	})

	t.Run("Test expire functionality", func(t *testing.T) {
		// Clear queue
		client.Del(ctx, testKey)

		// Log a message
		logger.Warn("Test expire")
		time.Sleep(100 * time.Millisecond)

		// Check TTL is set (should be 6 hours = 21600 seconds)
		ttl := client.TTL(ctx, testKey).Val()
		assert.Greater(t, ttl.Seconds(), float64(0), "TTL should be set")
		assert.LessOrEqual(t, ttl.Seconds(), float64(6*3600), "TTL should be <= 6 hours")
	})

	t.Run("Test log format", func(t *testing.T) {
		// Clear queue
		client.Del(ctx, testKey)

		// Log with different fields
		logger.WithField("user", "test_user").Error("Test with fields")
		time.Sleep(100 * time.Millisecond)

		// Get the log entry
		logLine := client.LIndex(ctx, testKey, 0).Val()

		// Verify log format contains expected fields
		assert.Contains(t, logLine, "level=error")
		assert.Contains(t, logLine, "msg=\"Test with fields\"")
		assert.Contains(t, logLine, "user=test_user")
		// Should not contain colors (DisableColors: true)
		assert.False(t, strings.Contains(logLine, "\x1b["), "Log should not contain color codes")
	})
}

// BenchmarkLogrusRedisHook benchmarks the performance of Redis hook
func BenchmarkLogrusRedisHook(b *testing.B) {
	ctx := context.Background()
	redisURI := "redis://:1pa2YgE3jfTbVVpn06CN@192.168.7.2:6379/0"

	opt, err := redis.ParseURL(redisURI)
	if err != nil {
		b.Skipf("Failed to parse Redis URI, skipping benchmark: %v", err)
		return
	}

	client := redis.NewClient(opt)
	defer client.Close()

	benchKey := "ada:logs_queue:bench_redis_hook"
	defer client.Del(ctx, benchKey)

	logger := logrus.New()
	logger.SetReportCaller(true)

	hook := NewLogrusRedis(client, benchKey)
	logger.AddHook(hook)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Error("Benchmark test message")
	}

	// Cleanup
	client.Del(ctx, benchKey)
}
