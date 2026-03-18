package scgo

import (
	"context"
)

func (s *Service) WithContext(ctx context.Context) *Service {
	if s == nil {
		return nil
	}

	clone := *s
	if ctx != nil {
		clone.ctx = ctx
	}
	return &clone
}

func (s *Service) withContext(ctx context.Context) *Service {
	return s.WithContext(ctx)
}

func (s *Service) mongoContext() context.Context {
	if s != nil && s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
