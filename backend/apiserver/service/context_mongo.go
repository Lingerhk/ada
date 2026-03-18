package service

import (
	"context"

	"ada/backend/apiserver/config"
)

func bindMongoContext(env *config.Env, ctx context.Context) *config.Env {
	return env.WithMongoContext(ctx)
}

func (s *ADAServiceV2) withContext(ctx context.Context) *ADAServiceV2 {
	if s == nil {
		return nil
	}

	clone := *s
	clone.env = bindMongoContext(s.env, ctx)
	return &clone
}

func (s *GrpcService) withContext(ctx context.Context) *GrpcService {
	if s == nil {
		return nil
	}

	clone := *s
	clone.env = bindMongoContext(s.env, ctx)
	return &clone
}
