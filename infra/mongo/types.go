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
	FindOne(name string, query, result interface{}) (err error, exist bool)
	Find(name string, query, result interface{}, limit int64) error
	FindAll(name string, query, result interface{}) error
	FindByLimitAndSkip(name string, query, result interface{}, limit, skip int64) error

	FindWithSelect(name string, query, selection, result interface{}, limit int64) error
	FindSelect(name string, query, selection, result interface{}) error
	FindWithMultiple(name string, query, selection, sorter, result interface{}, limit, skip int64) error

	FindCount(name string, query interface{}) (c int64, err error)
	FindSortByLimitAndSkip(name string, query, sorter, result interface{}, limit, skip int64) error

	FindWithAggregation(name string, pipeline, result interface{}) error

	Remove(name string, query interface{}, multi bool) error
	RemoveById(name string, id interface{}) error

	Drop(name string) error

	Insert(name string, doc interface{}) error
	InsertAll(name string, docs ...interface{}) error

	Update(name string, query, update interface{}, multi bool) error
	UpdateById(name string, id, update interface{}) error // id 为_id 的原类型, eg: ObjectID, int
	UpdateRaw(name string, query, update interface{}, multi bool) error

	GetNextSequence(name string) (int32, error)

	FindWithDistinct(name, distinct string, query interface{}) ([]interface{}, error)
}
