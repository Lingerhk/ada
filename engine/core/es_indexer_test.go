package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/elastic/go-elasticsearch/v8"
)

func TestESIndexerRetriesAndTracksStats(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Elastic-Product", "Elasticsearch")
		if calls.Add(1) < 3 {
			http.Error(w, `{"error":"temporary"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"errors":false,"items":[]}`))
	}))
	t.Cleanup(srv.Close)

	es, err := elasticsearch.NewClient(elasticsearch.Config{Addresses: []string{srv.URL}})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	indexer := NewESIndexer(ctx, es, "ada-test", 100, time.Hour)
	indexer.retryBaseDelay = time.Millisecond
	indexer.EnqueueBytes("doc-1", []byte(`{"message":"ok"}`))

	if err := indexer.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 3 {
		t.Fatalf("expected 3 bulk attempts, got %d", got)
	}

	stats := indexer.Stats()
	if stats.EnqueuedItems != 1 || stats.FlushBatches != 1 || stats.IndexedItems != 1 || stats.RetryAttempts != 2 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	if stats.FailedBatches != 0 || stats.DroppedItems != 0 || stats.LastError != "" {
		t.Fatalf("unexpected failure stats after successful retry: %#v", stats)
	}
}
