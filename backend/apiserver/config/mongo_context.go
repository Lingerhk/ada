package config

import "context"

func (e *Env) WithMongoContext(ctx context.Context) *Env {
	if e == nil || ctx == nil || e.MongoCli == nil {
		return e
	}

	clone := *e
	clone.ctx = ctx
	return &clone
}

func (e *Env) MongoContext() context.Context {
	if e != nil && e.ctx != nil {
		return e.ctx
	}
	return context.Background()
}
