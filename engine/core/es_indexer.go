package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	logger "github.com/sirupsen/logrus"
)

// ESIndexer batches documents and writes them via Bulk API.
// It keeps bounded in-memory retry behavior; failed batches are dropped after retry budget is exhausted.
type ESIndexer struct {
	ctx context.Context
	es  *elasticsearch.Client

	index          string
	flushMaxItems  int
	flushInterval  time.Duration
	maxRetries     int
	retryBaseDelay time.Duration

	mu     sync.Mutex
	buf    []bulkItem
	wakeCh chan struct{}
	stats  ESIndexerStats
}

type ESIndexerStats struct {
	EnqueuedItems uint64
	FlushBatches  uint64
	IndexedItems  uint64
	RetryAttempts uint64
	FailedBatches uint64
	DroppedItems  uint64
	LastError     string
}

type bulkItem struct {
	id   string
	body []byte
}

func NewESIndexer(ctx context.Context, es *elasticsearch.Client, index string, flushMaxItems int, flushInterval time.Duration) *ESIndexer {
	i := &ESIndexer{
		ctx:            ctx,
		es:             es,
		index:          index,
		flushMaxItems:  flushMaxItems,
		flushInterval:  flushInterval,
		maxRetries:     3,
		retryBaseDelay: 200 * time.Millisecond,
		wakeCh:         make(chan struct{}, 1),
	}

	go i.loop()
	return i
}

func (i *ESIndexer) Enqueue(id string, doc any) {
	if i == nil || i.es == nil {
		return
	}
	b, err := json.Marshal(doc)
	if err != nil {
		logger.Errorf("es indexer marshal err: %v", err)
		return
	}
	i.EnqueueBytes(id, b)
}

func (i *ESIndexer) EnqueueBytes(id string, body []byte) {
	if i == nil || i.es == nil {
		return
	}

	i.mu.Lock()
	i.buf = append(i.buf, bulkItem{id: id, body: body})
	i.stats.EnqueuedItems++
	n := len(i.buf)
	i.mu.Unlock()

	if n >= i.flushMaxItems {
		select {
		case i.wakeCh <- struct{}{}:
		default:
		}
	}
}

func (i *ESIndexer) loop() {
	t := time.NewTicker(i.flushInterval)
	defer t.Stop()

	for {
		select {
		case <-i.ctx.Done():
			_ = i.Flush()
			return
		case <-t.C:
			_ = i.Flush()
		case <-i.wakeCh:
			_ = i.Flush()
		}
	}
}

func (i *ESIndexer) Flush() error {
	if i == nil || i.es == nil {
		return nil
	}

	i.mu.Lock()
	if len(i.buf) == 0 {
		i.mu.Unlock()
		return nil
	}
	items := i.buf
	i.buf = nil
	i.stats.FlushBatches++
	i.mu.Unlock()

	// Build NDJSON payload.
	var b bytes.Buffer
	for _, it := range items {
		meta := fmt.Sprintf("{\"index\":{\"_index\":%q,\"_id\":%q}}\n", i.index, it.id)
		b.WriteString(meta)
		b.Write(it.body)
		b.WriteByte('\n')
	}

	return i.flushPayloadWithRetry(b.Bytes(), len(items))
}

func (i *ESIndexer) Stats() ESIndexerStats {
	if i == nil {
		return ESIndexerStats{}
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.stats
}

func (i *ESIndexer) flushPayloadWithRetry(payload []byte, itemCount int) error {
	var lastErr error
	attempts := i.maxRetries + 1
	if attempts < 1 {
		attempts = 1
	}

	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			i.recordRetry()
			if !i.waitRetryDelay(attempt) {
				return i.dropFailedBatch(itemCount, i.ctx.Err())
			}
		}

		req := esapi.BulkRequest{Body: bytes.NewReader(payload)}
		res, err := req.Do(i.ctx, i.es)
		if err != nil {
			lastErr = err
			logger.Warnf("es bulk request err: %v (items=%d attempt=%d/%d)", err, itemCount, attempt+1, attempts)
			continue
		}

		if res.IsError() {
			lastErr = fmt.Errorf("bulk status: %s", res.Status())
			logger.Warnf("es bulk response err: %s (items=%d attempt=%d/%d)", res.Status(), itemCount, attempt+1, attempts)
			_ = res.Body.Close()
			continue
		}
		_ = res.Body.Close()

		i.mu.Lock()
		i.stats.IndexedItems += uint64(itemCount)
		i.stats.LastError = ""
		i.mu.Unlock()
		return nil
	}

	return i.dropFailedBatch(itemCount, lastErr)
}

func (i *ESIndexer) recordRetry() {
	i.mu.Lock()
	i.stats.RetryAttempts++
	i.mu.Unlock()
}

func (i *ESIndexer) waitRetryDelay(attempt int) bool {
	delay := i.retryBaseDelay
	if delay <= 0 {
		return true
	}
	for j := 1; j < attempt; j++ {
		delay *= 2
		if delay > 2*time.Second {
			delay = 2 * time.Second
			break
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-i.ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (i *ESIndexer) dropFailedBatch(itemCount int, err error) error {
	if err == nil {
		err = fmt.Errorf("bulk request failed")
	}
	logger.Errorf("es bulk dropped batch after retries: %v (items=%d)", err, itemCount)
	i.mu.Lock()
	i.stats.FailedBatches++
	i.stats.DroppedItems += uint64(itemCount)
	i.stats.LastError = err.Error()
	i.mu.Unlock()
	return err
}
