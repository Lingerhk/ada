package config

import (
	"context"
	"testing"
)

type stubMongoAdaptor struct {
	findOneContextCalled bool
	findOneCalled        bool
	gotCtx               context.Context
}

func (s *stubMongoAdaptor) Connect(uri, db string) error { return nil }

func (s *stubMongoAdaptor) Disconnect() {}

func (s *stubMongoAdaptor) SetPoolLimit(limit uint64) {}

func (s *stubMongoAdaptor) FindOne(name string, query, result any) (err error, exist bool) {
	s.findOneCalled = true
	return nil, true
}

func (s *stubMongoAdaptor) Find(name string, query, result any, limit int64) error { return nil }

func (s *stubMongoAdaptor) FindAll(name string, query, result any) error { return nil }

func (s *stubMongoAdaptor) FindByLimitAndSkip(name string, query, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithSelect(name string, query, selection, result any, limit int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindSelect(name string, query, selection, result any) error { return nil }

func (s *stubMongoAdaptor) FindWithMultiple(name string, query, selection, sorter, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindCount(name string, query any) (c int64, err error) { return 0, nil }

func (s *stubMongoAdaptor) FindSortByLimitAndSkip(name string, query, sorter, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithAggregation(name string, pipeline, result any) error { return nil }

func (s *stubMongoAdaptor) Remove(name string, query any, multi bool) error { return nil }

func (s *stubMongoAdaptor) RemoveById(name string, id any) error { return nil }

func (s *stubMongoAdaptor) Drop(name string) error { return nil }

func (s *stubMongoAdaptor) Insert(name string, doc any) error { return nil }

func (s *stubMongoAdaptor) InsertAll(name string, docs ...any) error { return nil }

func (s *stubMongoAdaptor) Update(name string, query, update any, multi bool) error { return nil }

func (s *stubMongoAdaptor) UpdateById(name string, id, update any) error { return nil }

func (s *stubMongoAdaptor) UpdateRaw(name string, query, update any, multi bool) error { return nil }

func (s *stubMongoAdaptor) GetNextSequence(name string) (int32, error) { return 0, nil }

func (s *stubMongoAdaptor) FindWithDistinct(name, distinct string, query any) ([]any, error) {
	return nil, nil
}

func (s *stubMongoAdaptor) ConnectContext(ctx context.Context, uri, db string) error { return nil }

func (s *stubMongoAdaptor) DisconnectContext(ctx context.Context) {}

func (s *stubMongoAdaptor) FindOneContext(ctx context.Context, name string, query, result any) (err error, exist bool) {
	s.findOneContextCalled = true
	s.gotCtx = ctx
	return nil, true
}

func (s *stubMongoAdaptor) FindContext(ctx context.Context, name string, query, result any, limit int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindAllContext(ctx context.Context, name string, query, result any) error {
	return nil
}

func (s *stubMongoAdaptor) FindByLimitAndSkipContext(ctx context.Context, name string, query, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithSelectContext(ctx context.Context, name string, query, selection, result any, limit int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindSelectContext(ctx context.Context, name string, query, selection, result any) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithMultipleContext(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindCountContext(ctx context.Context, name string, query any) (c int64, err error) {
	return 0, nil
}

func (s *stubMongoAdaptor) FindSortByLimitAndSkipContext(ctx context.Context, name string, query any, sorter, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithAggregationContext(ctx context.Context, name string, pipeline, result any) error {
	return nil
}

func (s *stubMongoAdaptor) RemoveContext(ctx context.Context, name string, query any, multi bool) error {
	return nil
}

func (s *stubMongoAdaptor) RemoveByIdContext(ctx context.Context, name string, id any) error {
	return nil
}

func (s *stubMongoAdaptor) DropContext(ctx context.Context, name string) error { return nil }

func (s *stubMongoAdaptor) InsertContext(ctx context.Context, name string, doc any) error { return nil }

func (s *stubMongoAdaptor) InsertAllContext(ctx context.Context, name string, docs ...any) error {
	return nil
}

func (s *stubMongoAdaptor) UpdateContext(ctx context.Context, name string, query, update any, multi bool) error {
	return nil
}

func (s *stubMongoAdaptor) UpdateByIdContext(ctx context.Context, name string, id, update any) error {
	return nil
}

func (s *stubMongoAdaptor) UpdateRawContext(ctx context.Context, name string, query, update any, multi bool) error {
	return nil
}

func (s *stubMongoAdaptor) GetNextSequenceContext(ctx context.Context, name string) (int32, error) {
	return 0, nil
}

func (s *stubMongoAdaptor) FindWithDistinctContext(ctx context.Context, name, distinct string, query any) ([]any, error) {
	return nil, nil
}

func TestEnvWithMongoContextUsesContextAwareMethods(t *testing.T) {
	base := &stubMongoAdaptor{}
	env := &Env{MongoCli: base}
	ctx := context.WithValue(context.Background(), "request-id", "ctx-test")

	bound := env.WithMongoContext(ctx)
	if bound == env {
		t.Fatalf("expected WithMongoContext to clone env")
	}

	var result struct{}
	if _, ok := bound.MongoCli.FindOne("tb_users", nil, &result); !ok {
		t.Fatalf("expected find to report success")
	}

	if !base.findOneContextCalled {
		t.Fatalf("expected FindOneContext to be used")
	}
	if base.findOneCalled {
		t.Fatalf("expected FindOne fallback to remain unused")
	}
	if base.gotCtx != ctx {
		t.Fatalf("expected bound context to be forwarded")
	}
}

func TestEnvWithMongoContextHandlesNilInputs(t *testing.T) {
	var nilEnv *Env
	if got := nilEnv.WithMongoContext(context.Background()); got != nil {
		t.Fatalf("expected nil env to stay nil")
	}

	base := &stubMongoAdaptor{}
	env := &Env{MongoCli: base}
	if got := env.WithMongoContext(nil); got != env {
		t.Fatalf("expected nil context to reuse original env")
	}
}
