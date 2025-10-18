package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/bson"
)

// TestFindAllSystemLogs tests the FindAllSystemLogs function with MongoDB data
func TestFindAllSystemLogs(t *testing.T) {
	if env == nil {
		t.Skip("Skipping test: env not initialized")
		return
	}

	// Setup: Insert test log data into MongoDB
	testModule := "test_apiserver"
	collectionName := "tb_system_logs"

	// Clean up before test - remove all test logs
	env.MongoCli.Remove(collectionName, bson.M{"module": testModule}, true)
	defer env.MongoCli.Remove(collectionName, bson.M{"module": testModule}, true)

	// Parse test times
	time1, _ := time.Parse(time.RFC3339, "2025-10-17T14:03:08Z")
	time2, _ := time.Parse(time.RFC3339, "2025-10-17T14:03:09Z")
	time3, _ := time.Parse(time.RFC3339, "2025-10-17T14:03:10Z")

	// Insert test logs using the internal structure (time.Time for MongoDB)
	testLogs := []interface{}{
		bson.M{
			"time":   time1,
			"level":  "error",
			"module": testModule,
			"msg":    "test error 1",
			"func":   "test.Func1",
			"file":   "test.go:1",
		},
		bson.M{
			"time":   time2,
			"level":  "warn",
			"module": testModule,
			"msg":    "test warning 1",
			"func":   "test.Func2",
			"file":   "test.go:2",
		},
		bson.M{
			"time":   time3,
			"level":  "error",
			"module": testModule,
			"msg":    "test error 2",
			"func":   "test.Func3",
			"file":   "test.go:3",
		},
	}

	err := env.MongoCli.InsertAll(collectionName, testLogs...)
	assert.NoError(t, err)

	// Test 1: Get all logs without filters
	t.Run("Get all logs", func(t *testing.T) {
		logs, total, err := FindAllSystemLogs(env, []string{}, []string{testModule}, "", "", "", -1, 10, 0)
		assert.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Equal(t, 3, len(logs))
	})

	// Test 2: Filter by level (error only)
	t.Run("Filter by error level", func(t *testing.T) {
		logs, total, err := FindAllSystemLogs(env, []string{"error"}, []string{testModule}, "", "", "", -1, 10, 0)
		assert.NoError(t, err)
		assert.Equal(t, int64(2), total)
		assert.Equal(t, 2, len(logs))
		for _, log := range logs {
			assert.Equal(t, "error", log.Level)
		}
	})

	// Test 3: Filter by search term
	t.Run("Filter by search term", func(t *testing.T) {
		logs, total, err := FindAllSystemLogs(env, []string{}, []string{testModule}, "warning", "", "", -1, 10, 0)
		assert.NoError(t, err)
		assert.Equal(t, int64(1), total)
		assert.Equal(t, 1, len(logs))
		assert.Contains(t, logs[0].Msg, "warning")
	})

	// Test 4: Pagination
	t.Run("Pagination", func(t *testing.T) {
		// Get first page
		logs, total, err := FindAllSystemLogs(env, []string{}, []string{testModule}, "", "", "", -1, 2, 0)
		assert.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Equal(t, 2, len(logs))

		// Get second page
		logs, total, err = FindAllSystemLogs(env, []string{}, []string{testModule}, "", "", "", -1, 2, 2)
		assert.NoError(t, err)
		assert.Equal(t, int64(3), total)
		assert.Equal(t, 1, len(logs))
	})

	// Test 5: Sort order (ascending vs descending)
	t.Run("Sort order", func(t *testing.T) {
		// Descending (default)
		logsDesc, _, err := FindAllSystemLogs(env, []string{}, []string{testModule}, "", "", "", -1, 10, 0)
		assert.NoError(t, err)

		// Ascending
		logsAsc, _, err := FindAllSystemLogs(env, []string{}, []string{testModule}, "", "", "", 1, 10, 0)
		assert.NoError(t, err)

		// First element in descending should be last in ascending
		assert.Equal(t, logsDesc[0].Time, logsAsc[len(logsAsc)-1].Time)
	})

	// Test 6: Time range filter
	t.Run("Time range filter", func(t *testing.T) {
		startTime := "2025-10-17 14:03:09"
		endTime := "2025-10-17 14:03:11"

		logs, total, err := FindAllSystemLogs(env, []string{}, []string{testModule}, "", startTime, endTime, -1, 10, 0)
		assert.NoError(t, err)
		// Should return logs within time range (log 2 and log 3)
		assert.LessOrEqual(t, int(total), 2)

		// All logs should be within the time range
		for _, log := range logs {
			logTime, err := time.Parse(time.RFC3339, log.Time)
			assert.NoError(t, err)

			start, err := time.Parse("2006-01-02 15:04:05", startTime)
			assert.NoError(t, err)

			end, err := time.Parse("2006-01-02 15:04:05", endTime)
			assert.NoError(t, err)

			assert.True(t, !logTime.Before(start) && !logTime.After(end))
		}
	})
}

// TestFindAllSystemLogsEmptyQuery tests behavior with nonexistent module
func TestFindAllSystemLogsEmptyQuery(t *testing.T) {
	if env == nil {
		t.Skip("Skipping test: env not initialized")
		return
	}

	logs, total, err := FindAllSystemLogs(env, []string{}, []string{"nonexistent_module"}, "", "", "", -1, 10, 0)
	assert.NoError(t, err)
	assert.Equal(t, int64(0), total)
	assert.Equal(t, 0, len(logs))
}
