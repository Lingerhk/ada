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
// It is best-effort: on failures it logs and drops items (can be extended to retry/persist).
type ESIndexer struct {
	ctx context.Context
	es  *elasticsearch.Client

	index         string
	flushMaxItems int
	flushInterval time.Duration

	mu     sync.Mutex
	buf    []bulkItem
	wakeCh chan struct{}
}

type bulkItem struct {
	id   string
	body []byte
}

func NewESIndexer(ctx context.Context, es *elasticsearch.Client, index string, flushMaxItems int, flushInterval time.Duration) *ESIndexer {
	i := &ESIndexer{
		ctx:           ctx,
		es:            es,
		index:         index,
		flushMaxItems: flushMaxItems,
		flushInterval: flushInterval,
		wakeCh:        make(chan struct{}, 1),
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
	i.mu.Unlock()

	// Build NDJSON payload.
	var b bytes.Buffer
	for _, it := range items {
		meta := fmt.Sprintf("{\"index\":{\"_index\":%q,\"_id\":%q}}\n", i.index, it.id)
		b.WriteString(meta)
		b.Write(it.body)
		b.WriteByte('\n')
	}

	req := esapi.BulkRequest{Body: bytes.NewReader(b.Bytes())}
	res, err := req.Do(i.ctx, i.es)
	if err != nil {
		logger.Errorf("es bulk request err: %v (items=%d)", err, len(items))
		return err
	}
	defer res.Body.Close()

	if res.IsError() {
		logger.Errorf("es bulk response err: %s (items=%d)", res.Status(), len(items))
		return fmt.Errorf("bulk status: %s", res.Status())
	}

	return nil
}
