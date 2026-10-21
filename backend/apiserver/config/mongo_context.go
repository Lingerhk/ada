package config

import "context"

// WithMongoContext returns a copy of e whose MongoDB calls use ctx.
func (e *Env) WithMongoContext(ctx context.Context) *Env {
	if e == nil || ctx == nil || e.MongoCli == nil {
		return e
	}

	clone := *e
	clone.Ctx = e.Ctx.With(ctx)
	return &clone
}

// MongoContext returns the context bound to e (Background when unset).
func (e *Env) MongoContext() context.Context {
	if e == nil {
		return context.Background()
	}
	return e.Ctx.Context()
}
