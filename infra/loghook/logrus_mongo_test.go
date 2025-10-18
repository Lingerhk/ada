package loghook

import (
	"ada/infra/mongo"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// TestLogrusMongoHook tests the MongoDB hook functionality
func TestLogrusMongoHook(t *testing.T) {
	// Connect to MongoDB using DBAdaptor
	testDB := "db_ada"
	testModule := "test_module"

	mongoCli := mongo.NewMongoSession()
	mongoURI := "mongodb://user_ada:XEl44B4p3hFurztFMo38@192.168.7.2:27017/db_ada?authSource=db_ada"
	err := mongoCli.Connect(mongoURI, testDB)
	if err != nil {
		t.Skipf("MongoDB not available, skipping test: %v", err)
		return
	}
	defer mongoCli.Disconnect()

	// Clean up test collection before test
	testCollection := "test_system_logs"
	mongoCli.Drop(testCollection)
	defer mongoCli.Drop(testCollection)

	// Create logger with MongoDB hook
	logger := logrus.New()
	logger.SetReportCaller(true)

	hook := NewLogrusMongoHook(mongoCli, testModule)
	logger.AddHook(hook)

	// Test different log levels
	t.Run("Test log levels", func(t *testing.T) {
		logger.Info("This is info - should not be saved")
		logger.Debug("This is debug - should not be saved")
		logger.Warn("This is warning - should be saved")
		logger.Error("This is error - should be saved")

		// Wait a bit for async operations
		time.Sleep(100 * time.Millisecond)

		// Count documents in collection
		count, err := mongoCli.FindCount(testCollection, map[string]any{})
		assert.NoError(t, err)
		assert.Equal(t, int64(2), count, "Should have 2 logs (warn + error)")
	})

	t.Run("Test log content", func(t *testing.T) {
		// Clear collection
		mongoCli.Drop(testCollection)

		// Log a specific message
		logger.Error("Test error message")
		time.Sleep(100 * time.Millisecond)

		// Find the log entry
		var result SystemLog
		err, exist := mongoCli.FindOne(testCollection, map[string]any{}, &result)
		assert.NoError(t, err)
		assert.True(t, exist)
		assert.Equal(t, "error", result.Level)
		assert.Equal(t, testModule, result.Module)
		assert.Equal(t, "Test error message", result.Msg)
		assert.NotEmpty(t, result.Time)
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
}

// BenchmarkLogrusMongoHook benchmarks the performance of MongoDB hook
func BenchmarkLogrusMongoHook(b *testing.B) {
	mongoCli := mongo.NewMongoSession()
	mongoURI := "mongodb://user_ada:XEl44B4p3hFurztFMo38@192.168.7.2:27017/db_ada?authSource=db_ada"
	err := mongoCli.Connect(mongoURI, "db_ada")
	if err != nil {
		b.Skipf("MongoDB not available, skipping benchmark: %v", err)
		return
	}
	defer mongoCli.Disconnect()

	logger := logrus.New()
	logger.SetReportCaller(true)

	hook := NewLogrusMongoHook(mongoCli, "bench_module")
	logger.AddHook(hook)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logger.Error("Benchmark test message")
	}

	// Cleanup
	mongoCli.Drop("tb_system_logs")
}
