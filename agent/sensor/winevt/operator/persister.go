// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"context"
	"fmt"

	"ada/agent/sensor/winevt/storage"
)

// Persister is an interface used to persist data
type Persister interface {
	Get(context.Context, string) ([]byte, error)
	Set(context.Context, string, []byte) error
	Delete(context.Context, string) error
	Batch(ctx context.Context, ops ...*storage.Operation) error
}

// ////////////////////
// NoopPersister implements the operator.Persister interface but does nothing
type NoopPersister struct{}

// Get returns nil data and no error
func (p *NoopPersister) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, nil
}

// Set does nothing and returns no error
func (p *NoopPersister) Set(_ context.Context, _ string, _ []byte) error {
	return nil
}

// Delete does nothing and returns no error
func (p *NoopPersister) Delete(_ context.Context, _ string) error {
	return nil
}

// Batch does nothing and returns no error
func (p *NoopPersister) Batch(_ context.Context, ops ...*storage.Operation) error {
	return nil
}

//////////////////////

type scopedPersister struct {
	Persister
	scope string
}

func NewScopedPersister(s string, p Persister) Persister {
	return &scopedPersister{
		Persister: p,
		scope:     s,
	}
}

func (p scopedPersister) Get(ctx context.Context, key string) ([]byte, error) {
	return p.Persister.Get(ctx, fmt.Sprintf("%s.%s", p.scope, key))
}

func (p scopedPersister) Set(ctx context.Context, key string, value []byte) error {
	return p.Persister.Set(ctx, fmt.Sprintf("%s.%s", p.scope, key), value)
}

func (p scopedPersister) Delete(ctx context.Context, key string) error {
	return p.Persister.Delete(ctx, fmt.Sprintf("%s.%s", p.scope, key))
}

func (p scopedPersister) Batch(ctx context.Context, ops ...*storage.Operation) error {
	for _, op := range ops {
		op.Key = fmt.Sprintf("%s.%s", p.scope, op.Key)
	}
	return p.Persister.Batch(ctx, ops...)
}
