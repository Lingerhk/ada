package mongo

import "context"

type contextCapableAdaptor interface {
	DBAdaptor
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

type contextAdaptor struct {
	base    DBAdaptor
	ctx     context.Context
	capable contextCapableAdaptor
}

// BindContext wraps a DBAdaptor so its operations use ctx when context-aware
// Mongo helpers are available.
func BindContext(base DBAdaptor, ctx context.Context) DBAdaptor {
	if base == nil || ctx == nil {
		return base
	}

	if wrapped, ok := base.(*contextAdaptor); ok {
		base = wrapped.base
	}

	adaptor := &contextAdaptor{
		base: base,
		ctx:  ctx,
	}
	if capable, ok := base.(contextCapableAdaptor); ok {
		adaptor.capable = capable
	}

	return adaptor
}

func (a *contextAdaptor) Connect(uri, db string) error {
	if a.capable != nil {
		return a.capable.ConnectContext(a.ctx, uri, db)
	}
	return a.base.Connect(uri, db)
}

func (a *contextAdaptor) Disconnect() {
	if a.capable != nil {
		a.capable.DisconnectContext(a.ctx)
		return
	}
	a.base.Disconnect()
}

func (a *contextAdaptor) SetPoolLimit(limit uint64) {
	a.base.SetPoolLimit(limit)
}

func (a *contextAdaptor) FindOne(name string, query, result any) (err error, exist bool) {
	if a.capable != nil {
		return a.capable.FindOneContext(a.ctx, name, query, result)
	}
	return a.base.FindOne(name, query, result)
}

func (a *contextAdaptor) Find(name string, query, result any, limit int64) error {
	if a.capable != nil {
		return a.capable.FindContext(a.ctx, name, query, result, limit)
	}
	return a.base.Find(name, query, result, limit)
}

func (a *contextAdaptor) FindAll(name string, query, result any) error {
	if a.capable != nil {
		return a.capable.FindAllContext(a.ctx, name, query, result)
	}
	return a.base.FindAll(name, query, result)
}

func (a *contextAdaptor) FindByLimitAndSkip(name string, query, result any, limit, skip int64) error {
	if a.capable != nil {
		return a.capable.FindByLimitAndSkipContext(a.ctx, name, query, result, limit, skip)
	}
	return a.base.FindByLimitAndSkip(name, query, result, limit, skip)
}

func (a *contextAdaptor) FindWithSelect(name string, query, selection, result any, limit int64) error {
	if a.capable != nil {
		return a.capable.FindWithSelectContext(a.ctx, name, query, selection, result, limit)
	}
	return a.base.FindWithSelect(name, query, selection, result, limit)
}

func (a *contextAdaptor) FindSelect(name string, query, selection, result any) error {
	if a.capable != nil {
		return a.capable.FindSelectContext(a.ctx, name, query, selection, result)
	}
	return a.base.FindSelect(name, query, selection, result)
}

func (a *contextAdaptor) FindWithMultiple(name string, query, selection, sorter, result any, limit, skip int64) error {
	if a.capable != nil {
		return a.capable.FindWithMultipleContext(a.ctx, name, query, selection, sorter, result, limit, skip)
	}
	return a.base.FindWithMultiple(name, query, selection, sorter, result, limit, skip)
}

func (a *contextAdaptor) FindCount(name string, query any) (c int64, err error) {
	if a.capable != nil {
		return a.capable.FindCountContext(a.ctx, name, query)
	}
	return a.base.FindCount(name, query)
}

func (a *contextAdaptor) FindSortByLimitAndSkip(name string, query, sorter, result any, limit, skip int64) error {
	if a.capable != nil {
		return a.capable.FindSortByLimitAndSkipContext(a.ctx, name, query, sorter, result, limit, skip)
	}
	return a.base.FindSortByLimitAndSkip(name, query, sorter, result, limit, skip)
}

func (a *contextAdaptor) FindWithAggregation(name string, pipeline, result any) error {
	if a.capable != nil {
		return a.capable.FindWithAggregationContext(a.ctx, name, pipeline, result)
	}
	return a.base.FindWithAggregation(name, pipeline, result)
}

func (a *contextAdaptor) Remove(name string, query any, multi bool) error {
	if a.capable != nil {
		return a.capable.RemoveContext(a.ctx, name, query, multi)
	}
	return a.base.Remove(name, query, multi)
}

func (a *contextAdaptor) RemoveById(name string, id any) error {
	if a.capable != nil {
		return a.capable.RemoveByIdContext(a.ctx, name, id)
	}
	return a.base.RemoveById(name, id)
}

func (a *contextAdaptor) Drop(name string) error {
	if a.capable != nil {
		return a.capable.DropContext(a.ctx, name)
	}
	return a.base.Drop(name)
}

func (a *contextAdaptor) Insert(name string, doc any) error {
	if a.capable != nil {
		return a.capable.InsertContext(a.ctx, name, doc)
	}
	return a.base.Insert(name, doc)
}

func (a *contextAdaptor) InsertAll(name string, docs ...any) error {
	if a.capable != nil {
		return a.capable.InsertAllContext(a.ctx, name, docs...)
	}
	return a.base.InsertAll(name, docs...)
}

func (a *contextAdaptor) Update(name string, query, update any, multi bool) error {
	if a.capable != nil {
		return a.capable.UpdateContext(a.ctx, name, query, update, multi)
	}
	return a.base.Update(name, query, update, multi)
}

func (a *contextAdaptor) UpdateById(name string, id, update any) error {
	if a.capable != nil {
		return a.capable.UpdateByIdContext(a.ctx, name, id, update)
	}
	return a.base.UpdateById(name, id, update)
}

func (a *contextAdaptor) UpdateRaw(name string, query, update any, multi bool) error {
	if a.capable != nil {
		return a.capable.UpdateRawContext(a.ctx, name, query, update, multi)
	}
	return a.base.UpdateRaw(name, query, update, multi)
}

func (a *contextAdaptor) GetNextSequence(name string) (int32, error) {
	if a.capable != nil {
		return a.capable.GetNextSequenceContext(a.ctx, name)
	}
	return a.base.GetNextSequence(name)
}

func (a *contextAdaptor) FindWithDistinct(name, distinct string, query any) ([]any, error) {
	if a.capable != nil {
		return a.capable.FindWithDistinctContext(a.ctx, name, distinct, query)
	}
	return a.base.FindWithDistinct(name, distinct, query)
}
