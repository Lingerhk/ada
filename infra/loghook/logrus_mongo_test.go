package loghook

import (
	"ada/infra/mongo"
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"go.mongodb.org/mongo-driver/v2/bson"
)

var errUnsupported = errors.New("unsupported")

type fakeMongoAdaptor struct {
	mu          sync.Mutex
	collections map[string][]SystemLog
}

func newFakeMongoAdaptor() *fakeMongoAdaptor {
	return &fakeMongoAdaptor{
		collections: make(map[string][]SystemLog),
	}
}

func (f *fakeMongoAdaptor) Connect(ctx context.Context, uri, db string) error { return nil }
func (f *fakeMongoAdaptor) Disconnect(ctx context.Context)                    {}
func (f *fakeMongoAdaptor) SetPoolLimit(limit uint64)                         {}

func (f *fakeMongoAdaptor) FindOne(ctx context.Context, name string, query, result any) (error, bool) {
	return errUnsupported, false
}
func (f *fakeMongoAdaptor) Find(ctx context.Context, name string, query, result any, limit int64) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) FindAll(ctx context.Context, name string, query, result any) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) FindByLimitAndSkip(ctx context.Context, name string, query, result any, limit, skip int64) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) FindWithSelect(ctx context.Context, name string, query, selection, result any, limit int64) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) FindSelect(ctx context.Context, name string, query, selection, result any) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) FindWithMultiple(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error {
	return errUnsupported
}

func (f *fakeMongoAdaptor) FindCount(ctx context.Context, name string, query any) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int64(len(f.collections[name])), nil
}

func (f *fakeMongoAdaptor) FindSortByLimitAndSkip(ctx context.Context, name string, query, sorter, result any, limit, skip int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	dst, ok := result.(*[]SystemLog)
	if !ok {
		return mongo.ErrorResultType
	}

	logs := append([]SystemLog(nil), f.collections[name]...)
	sort.Slice(logs, func(i, j int) bool {
		return logs[i].Time.Before(logs[j].Time)
	})

	if skip >= int64(len(logs)) {
		*dst = nil
		return nil
	}
	end := skip + limit
	if end > int64(len(logs)) {
		end = int64(len(logs))
	}
	*dst = logs[skip:end]
	return nil
}

func (f *fakeMongoAdaptor) FindWithAggregation(ctx context.Context, name string, pipeline, result any) error {
	return errUnsupported
}

func (f *fakeMongoAdaptor) Remove(ctx context.Context, name string, query any, multi bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	q, ok := query.(bson.M)
	if !ok {
		return mongo.ErrUnknownType
	}
	timeFilter, ok := q["time"].(bson.M)
	if !ok {
		return mongo.ErrUnknownType
	}
	cutoff, ok := timeFilter["$lte"].(time.Time)
	if !ok {
		return mongo.ErrUnknownType
	}

	filtered := f.collections[name][:0]
	for _, item := range f.collections[name] {
		if item.Time.After(cutoff) {
			filtered = append(filtered, item)
		}
	}
	f.collections[name] = append([]SystemLog(nil), filtered...)
	return nil
}

func (f *fakeMongoAdaptor) RemoveById(ctx context.Context, name string, id any) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) Drop(ctx context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.collections, name)
	return nil
}

func (f *fakeMongoAdaptor) Insert(ctx context.Context, name string, doc any) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	logDoc, ok := doc.(SystemLog)
	if !ok {
		return mongo.ErrorResultType
	}
	f.collections[name] = append(f.collections[name], logDoc)
	return nil
}

func (f *fakeMongoAdaptor) InsertAll(ctx context.Context, name string, docs ...any) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) Update(ctx context.Context, name string, query, update any, multi bool) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) UpdateById(ctx context.Context, name string, id, update any) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) UpdateRaw(ctx context.Context, name string, query, update any, multi bool) error {
	return errUnsupported
}
func (f *fakeMongoAdaptor) GetNextSequence(ctx context.Context, name string) (int32, error) {
	return 0, errUnsupported
}
func (f *fakeMongoAdaptor) FindWithDistinct(ctx context.Context, name, distinct string, query any) ([]any, error) {
	return nil, errUnsupported
}

func (f *fakeMongoAdaptor) count(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.collections[name])
}

func (f *fakeMongoAdaptor) first(name string) SystemLog {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.collections[name]) == 0 {
		return SystemLog{}
	}
	return f.collections[name][0]
}

func TestLogrusMongoHook(t *testing.T) {
	testModule := "test_module"
	mongoCli := newFakeMongoAdaptor()

	logger := logrus.New()
	logger.SetReportCaller(true)

	hook := NewLogrusMongoHook(mongoCli, testModule)
	logger.AddHook(hook)

	t.Run("Test log levels", func(t *testing.T) {
		_ = mongoCli.Drop(context.Background(), defaultMongoCollName)

		logger.Info("This is info - should not be saved")
		logger.Debug("This is debug - should not be saved")
		logger.Warn("This is warning - should be saved")
		logger.Error("This is error - should be saved")

		assert.Equal(t, 2, mongoCli.count(defaultMongoCollName), "Should have 2 logs (warn + error)")
	})

	t.Run("Test log content", func(t *testing.T) {
		_ = mongoCli.Drop(context.Background(), defaultMongoCollName)

		logger.Error("Test error message")

		result := mongoCli.first(defaultMongoCollName)
		assert.Equal(t, "error", result.Level)
		assert.Equal(t, testModule, result.Module)
		assert.Equal(t, "Test error message", result.Msg)
		assert.NotEmpty(t, result.Time)
		assert.NotEmpty(t, result.File)
	})

	t.Run("Test trimming contract", func(t *testing.T) {
		_ = mongoCli.Drop(context.Background(), defaultMongoCollName)

		baseTime := time.Now().Add(-time.Hour)
		for i := 0; i < defaultMaxLogsSize; i++ {
			assert.NoError(t, mongoCli.Insert(context.Background(), defaultMongoCollName, SystemLog{
				Time:   baseTime.Add(time.Duration(i) * time.Second),
				Level:  "warn",
				Module: testModule,
				Msg:    "seed",
			}))
		}

		logger.Error("New log after limit")

		assert.Equal(t, defaultMaxLogsSize-defaultTrimBatchSize+1, mongoCli.count(defaultMongoCollName))
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
