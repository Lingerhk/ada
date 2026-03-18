package mongo

import (
	"context"
	"errors"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrorResultType = errors.New("error result type")
	ErrorLimit      = errors.New("find limit is invalid,must be -1 or > 0")
	ErrIsDuplicate  = errors.New("error duplicate key")
	ErrUnknownType  = errors.New("error unknown type")
)

// DBAdaptor encapsulates MongoDB database operation interface
type DBAdaptor interface {
	Connect(ctx context.Context, uri, db string) error
	Disconnect(ctx context.Context)
	SetPoolLimit(limit uint64)

	// Common operation interfaces
	FindOne(ctx context.Context, name string, query, result any) (err error, exist bool)
	Find(ctx context.Context, name string, query, result any, limit int64) error
	FindAll(ctx context.Context, name string, query, result any) error
	FindByLimitAndSkip(ctx context.Context, name string, query, result any, limit, skip int64) error

	FindWithSelect(ctx context.Context, name string, query, selection, result any, limit int64) error
	FindSelect(ctx context.Context, name string, query, selection, result any) error
	FindWithMultiple(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error

	FindCount(ctx context.Context, name string, query any) (c int64, err error)
	FindSortByLimitAndSkip(ctx context.Context, name string, query, sorter, result any, limit, skip int64) error

	FindWithAggregation(ctx context.Context, name string, pipeline, result any) error

	Remove(ctx context.Context, name string, query any, multi bool) error
	RemoveById(ctx context.Context, name string, id any) error

	Drop(ctx context.Context, name string) error

	Insert(ctx context.Context, name string, doc any) error
	InsertAll(ctx context.Context, name string, docs ...any) error

	Update(ctx context.Context, name string, query, update any, multi bool) error
	UpdateById(ctx context.Context, name string, id, update any) error // id is the original type of _id, eg: ObjectID, int
	UpdateRaw(ctx context.Context, name string, query, update any, multi bool) error

	GetNextSequence(ctx context.Context, name string) (int32, error)

	FindWithDistinct(ctx context.Context, name, distinct string, query any) ([]any, error)
}
