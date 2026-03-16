package config

import (
	"context"

	"ada/infra/mongo"
)

type mongoContextCapable interface {
	mongo.DBAdaptor
	ConnectContext(ctx context.Context, uri, db string) error
	DisconnectContext(ctx context.Context)
	FindOneContext(ctx context.Context, name string, query, result any) (err error, exist bool)
	FindContext(ctx context.Context, name string, query, result any, limit int64) error
	FindAllContext(ctx context.Context, name string, query, result any) error
	FindByLimitAndSkipContext(ctx context.Context, name string, query, result any, limit, skip int64) error
	FindWithSelectContext(ctx context.Context, name string, query, selection, result any, limit int64) error
	FindSelectContext(ctx context.Context, name string, query, selection, result any) error
	FindWithMultipleContext(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error
	FindCountContext(ctx context.Context, name string, query any) (c int64, err error)
	FindSortByLimitAndSkipContext(ctx context.Context, name string, query any, sorter, result any, limit, skip int64) error
	FindWithAggregationContext(ctx context.Context, name string, pipeline, result any) error
	RemoveContext(ctx context.Context, name string, query any, multi bool) error
	RemoveByIdContext(ctx context.Context, name string, id any) error
	DropContext(ctx context.Context, name string) error
	InsertContext(ctx context.Context, name string, doc any) error
	InsertAllContext(ctx context.Context, name string, docs ...any) error
	UpdateContext(ctx context.Context, name string, query, update any, multi bool) error
	UpdateByIdContext(ctx context.Context, name string, id, update any) error
	UpdateRawContext(ctx context.Context, name string, query, update any, multi bool) error
	GetNextSequenceContext(ctx context.Context, name string) (int32, error)
	FindWithDistinctContext(ctx context.Context, name, distinct string, query any) ([]any, error)
}

type mongoContextAdaptor struct {
	base    mongo.DBAdaptor
	ctx     context.Context
	capable mongoContextCapable
}

func (e *Env) WithMongoContext(ctx context.Context) *Env {
	if e == nil || ctx == nil || e.MongoCli == nil {
		return e
	}

	clone := *e
	clone.MongoCli = bindMongoContext(e.MongoCli, ctx)
	return &clone
}

func bindMongoContext(base mongo.DBAdaptor, ctx context.Context) mongo.DBAdaptor {
	if base == nil || ctx == nil {
		return base
	}

	if wrapped, ok := base.(*mongoContextAdaptor); ok {
		base = wrapped.base
	}

	adaptor := &mongoContextAdaptor{
		base: base,
		ctx:  ctx,
	}
	if capable, ok := base.(mongoContextCapable); ok {
		adaptor.capable = capable
	}
	return adaptor
}

func (a *mongoContextAdaptor) Connect(uri, db string) error {
	if a.capable != nil {
		return a.capable.ConnectContext(a.ctx, uri, db)
	}
	return a.base.Connect(uri, db)
}

func (a *mongoContextAdaptor) Disconnect() {
	if a.capable != nil {
		a.capable.DisconnectContext(a.ctx)
		return
	}
	a.base.Disconnect()
}

func (a *mongoContextAdaptor) SetPoolLimit(limit uint64) {
	a.base.SetPoolLimit(limit)
}

func (a *mongoContextAdaptor) FindOne(name string, query, result any) (err error, exist bool) {
	if a.capable != nil {
		return a.capable.FindOneContext(a.ctx, name, query, result)
	}
	return a.base.FindOne(name, query, result)
}

func (a *mongoContextAdaptor) Find(name string, query, result any, limit int64) error {
	if a.capable != nil {
		return a.capable.FindContext(a.ctx, name, query, result, limit)
	}
	return a.base.Find(name, query, result, limit)
}

func (a *mongoContextAdaptor) FindAll(name string, query, result any) error {
	if a.capable != nil {
		return a.capable.FindAllContext(a.ctx, name, query, result)
	}
	return a.base.FindAll(name, query, result)
}

func (a *mongoContextAdaptor) FindByLimitAndSkip(name string, query, result any, limit, skip int64) error {
	if a.capable != nil {
		return a.capable.FindByLimitAndSkipContext(a.ctx, name, query, result, limit, skip)
	}
	return a.base.FindByLimitAndSkip(name, query, result, limit, skip)
}

func (a *mongoContextAdaptor) FindWithSelect(name string, query, selection, result any, limit int64) error {
	if a.capable != nil {
		return a.capable.FindWithSelectContext(a.ctx, name, query, selection, result, limit)
	}
	return a.base.FindWithSelect(name, query, selection, result, limit)
}

func (a *mongoContextAdaptor) FindSelect(name string, query, selection, result any) error {
	if a.capable != nil {
		return a.capable.FindSelectContext(a.ctx, name, query, selection, result)
	}
	return a.base.FindSelect(name, query, selection, result)
}

func (a *mongoContextAdaptor) FindWithMultiple(name string, query, selection, sorter, result any, limit, skip int64) error {
	if a.capable != nil {
		return a.capable.FindWithMultipleContext(a.ctx, name, query, selection, sorter, result, limit, skip)
	}
	return a.base.FindWithMultiple(name, query, selection, sorter, result, limit, skip)
}

func (a *mongoContextAdaptor) FindCount(name string, query any) (c int64, err error) {
	if a.capable != nil {
		return a.capable.FindCountContext(a.ctx, name, query)
	}
	return a.base.FindCount(name, query)
}

func (a *mongoContextAdaptor) FindSortByLimitAndSkip(name string, query, sorter, result any, limit, skip int64) error {
	if a.capable != nil {
		return a.capable.FindSortByLimitAndSkipContext(a.ctx, name, query, sorter, result, limit, skip)
	}
	return a.base.FindSortByLimitAndSkip(name, query, sorter, result, limit, skip)
}

func (a *mongoContextAdaptor) FindWithAggregation(name string, pipeline, result any) error {
	if a.capable != nil {
		return a.capable.FindWithAggregationContext(a.ctx, name, pipeline, result)
	}
	return a.base.FindWithAggregation(name, pipeline, result)
}

func (a *mongoContextAdaptor) Remove(name string, query any, multi bool) error {
	if a.capable != nil {
		return a.capable.RemoveContext(a.ctx, name, query, multi)
	}
	return a.base.Remove(name, query, multi)
}

func (a *mongoContextAdaptor) RemoveById(name string, id any) error {
	if a.capable != nil {
		return a.capable.RemoveByIdContext(a.ctx, name, id)
	}
	return a.base.RemoveById(name, id)
}

func (a *mongoContextAdaptor) Drop(name string) error {
	if a.capable != nil {
		return a.capable.DropContext(a.ctx, name)
	}
	return a.base.Drop(name)
}

func (a *mongoContextAdaptor) Insert(name string, doc any) error {
	if a.capable != nil {
		return a.capable.InsertContext(a.ctx, name, doc)
	}
	return a.base.Insert(name, doc)
}

func (a *mongoContextAdaptor) InsertAll(name string, docs ...any) error {
	if a.capable != nil {
		return a.capable.InsertAllContext(a.ctx, name, docs...)
	}
	return a.base.InsertAll(name, docs...)
}

func (a *mongoContextAdaptor) Update(name string, query, update any, multi bool) error {
	if a.capable != nil {
		return a.capable.UpdateContext(a.ctx, name, query, update, multi)
	}
	return a.base.Update(name, query, update, multi)
}

func (a *mongoContextAdaptor) UpdateById(name string, id, update any) error {
	if a.capable != nil {
		return a.capable.UpdateByIdContext(a.ctx, name, id, update)
	}
	return a.base.UpdateById(name, id, update)
}

func (a *mongoContextAdaptor) UpdateRaw(name string, query, update any, multi bool) error {
	if a.capable != nil {
		return a.capable.UpdateRawContext(a.ctx, name, query, update, multi)
	}
	return a.base.UpdateRaw(name, query, update, multi)
}

func (a *mongoContextAdaptor) GetNextSequence(name string) (int32, error) {
	if a.capable != nil {
		return a.capable.GetNextSequenceContext(a.ctx, name)
	}
	return a.base.GetNextSequence(name)
}

func (a *mongoContextAdaptor) FindWithDistinct(name, distinct string, query any) ([]any, error) {
	if a.capable != nil {
		return a.capable.FindWithDistinctContext(a.ctx, name, distinct, query)
	}
	return a.base.FindWithDistinct(name, distinct, query)
}
