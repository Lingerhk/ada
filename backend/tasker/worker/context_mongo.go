package worker

import (
	"context"
)

func (w *Worker) withContext(ctx context.Context) *Worker {
	if w == nil {
		return nil
	}
	clone := *w
	clone.env = w.env.WithMongoContext(ctx)
	return &clone
}
