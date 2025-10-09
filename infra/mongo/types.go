// author: adaegis
// time: 2023-12-01

package mongo

import (
	"errors"
)

var (
	ErrNotFound     = errors.New("not found")
	ErrorResultType = errors.New("error result type")
	ErrorLimit      = errors.New("find limit is invalid,must be -1 or > 0")
	ErrIsDuplicate  = errors.New("error duplicate key")
	ErrUnknownType  = errors.New("error unknown type")
)

// mongodb数据库操作接口封装
type DBAdaptor interface {
	Connect(uri, db string) error
	Disconnect()
	SetPoolLimit(limit uint64)

	// 常用操作接口
	FindOne(name string, query, result any) (err error, exist bool)
	Find(name string, query, result any, limit int64) error
	FindAll(name string, query, result any) error
	FindByLimitAndSkip(name string, query, result any, limit, skip int64) error

	FindWithSelect(name string, query, selection, result any, limit int64) error
	FindSelect(name string, query, selection, result any) error
	FindWithMultiple(name string, query, selection, sorter, result any, limit, skip int64) error

	FindCount(name string, query any) (c int64, err error)
	FindSortByLimitAndSkip(name string, query, sorter, result any, limit, skip int64) error

	FindWithAggregation(name string, pipeline, result any) error

	Remove(name string, query any, multi bool) error
	RemoveById(name string, id any) error

	Drop(name string) error

	Insert(name string, doc any) error
	InsertAll(name string, docs ...any) error

	Update(name string, query, update any, multi bool) error
	UpdateById(name string, id, update any) error // id 为_id 的原类型, eg: ObjectID, int
	UpdateRaw(name string, query, update any, multi bool) error

	GetNextSequence(name string) (int32, error)

	FindWithDistinct(name, distinct string, query any) ([]any, error)
}
