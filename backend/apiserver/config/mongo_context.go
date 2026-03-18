package config

import (
	"context"

	"ada/infra/mongo"
)

func (e *Env) WithMongoContext(ctx context.Context) *Env {
	if e == nil || ctx == nil || e.MongoCli == nil {
		return e
	}

	clone := *e
	clone.MongoCli = mongo.BindContext(e.MongoCli, ctx)
	return &clone
}
