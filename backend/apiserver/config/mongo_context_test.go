package config

import (
	"context"
	"testing"
)

type stubMongoAdaptor struct {
	gotCtx context.Context
}

func (s *stubMongoAdaptor) Connect(ctx context.Context, uri, db string) error { return nil }

func (s *stubMongoAdaptor) Disconnect(ctx context.Context) {}

func (s *stubMongoAdaptor) SetPoolLimit(limit uint64) {}

func (s *stubMongoAdaptor) FindOne(ctx context.Context, name string, query, result any) (err error, exist bool) {
	s.gotCtx = ctx
	return nil, true
}

func (s *stubMongoAdaptor) Find(ctx context.Context, name string, query, result any, limit int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindAll(ctx context.Context, name string, query, result any) error {
	return nil
}

func (s *stubMongoAdaptor) FindByLimitAndSkip(ctx context.Context, name string, query, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithSelect(ctx context.Context, name string, query, selection, result any, limit int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindSelect(ctx context.Context, name string, query, selection, result any) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithMultiple(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindCount(ctx context.Context, name string, query any) (c int64, err error) {
	return 0, nil
}

func (s *stubMongoAdaptor) FindSortByLimitAndSkip(ctx context.Context, name string, query any, sorter, result any, limit, skip int64) error {
	return nil
}

func (s *stubMongoAdaptor) FindWithAggregation(ctx context.Context, name string, pipeline, result any) error {
	return nil
}

func (s *stubMongoAdaptor) Remove(ctx context.Context, name string, query any, multi bool) error {
	return nil
}

func (s *stubMongoAdaptor) RemoveById(ctx context.Context, name string, id any) error {
	return nil
}

func (s *stubMongoAdaptor) Drop(ctx context.Context, name string) error { return nil }

func (s *stubMongoAdaptor) Insert(ctx context.Context, name string, doc any) error { return nil }

func (s *stubMongoAdaptor) InsertAll(ctx context.Context, name string, docs ...any) error {
	return nil
}

func (s *stubMongoAdaptor) Update(ctx context.Context, name string, query, update any, multi bool) error {
	return nil
}

func (s *stubMongoAdaptor) UpdateById(ctx context.Context, name string, id, update any) error {
	return nil
}

func (s *stubMongoAdaptor) UpdateRaw(ctx context.Context, name string, query, update any, multi bool) error {
	return nil
}

func (s *stubMongoAdaptor) GetNextSequence(ctx context.Context, name string) (int32, error) {
	return 0, nil
}

func (s *stubMongoAdaptor) FindWithDistinct(ctx context.Context, name, distinct string, query any) ([]any, error) {
	return nil, nil
}

func TestEnvWithMongoContextClonesEnvAndStoresContext(t *testing.T) {
	base := &stubMongoAdaptor{}
	env := &Env{MongoCli: base, ctx: context.Background()}
	ctx := context.WithValue(context.Background(), "request-id", "ctx-test")

	bound := env.WithMongoContext(ctx)
	if bound == env {
		t.Fatalf("expected WithMongoContext to clone env")
	}

	if bound.MongoContext() != ctx {
		t.Fatalf("expected bound context to be stored")
	}

	var result struct{}
	_, _ = bound.MongoCli.FindOne(bound.MongoContext(), "tb_users", nil, &result)
	if base.gotCtx != ctx {
		t.Fatalf("expected stored context to be forwarded")
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
