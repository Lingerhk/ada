package scgo

import (
	"context"

	"ada/infra/mongo"
)

func (s *Service) WithContext(ctx context.Context) *Service {
	if s == nil {
		return nil
	}

	clone := *s
	clone.MongoCli = mongo.BindContext(s.MongoCli, ctx)
	return &clone
}

func (s *Service) withContext(ctx context.Context) *Service {
	return s.WithContext(ctx)
}
