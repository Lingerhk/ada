package mongo

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type MongoSession struct {
	session *Session
	dbName  string
}

func NewMongoSession() *MongoSession {
	return &MongoSession{}
}

func (ms *MongoSession) WithContext(ctx context.Context) *MongoSession {
	if ms == nil {
		return nil
	}
	clone := *ms
	if ms.session != nil {
		clone.session = ms.session.WithContext(ctx)
	}
	return &clone
}

func (ms *MongoSession) Connect(uri, db string) error {
	return ms.ConnectContext(context.Background(), uri, db)
}

func (ms *MongoSession) ConnectContext(ctx context.Context, uri, db string) error {
	ms.session = New(uri)
	ms.dbName = db
	ms.session.SetDB(db)

	err := ms.session.ConnectContext(ctx)
	if err != nil {
		return err
	}

	return nil
}

func (ms *MongoSession) Disconnect() {
	ms.session.m.Lock()
	ms.session.Disconnect()
	ms.session.m.Unlock()
}

func (ms *MongoSession) SetPoolLimit(limit uint64) {
	ms.session.SetPoolLimit(limit)
}

// FindOne performs actual find one operation
func (ms *MongoSession) FindOne(name string, query, result any) (err error, exist bool) {
	return ms.FindOneContext(context.Background(), name, query, result)
}

func (ms *MongoSession) FindOneContext(ctx context.Context, name string, query, result any) (err error, exist bool) {
	exist = true
	err = ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).One(result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return ErrNotFound, false
		}
		return err, false
	}

	return err, exist
}

func (ms *MongoSession) Find(name string, query, result any, limit int64) error {
	return ms.FindContext(context.Background(), name, query, result, limit)
}

func (ms *MongoSession) FindContext(ctx context.Context, name string, query, result any, limit int64) error {
	if limit <= 0 {
		return ErrorLimit
	}

	err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Limit(limit).All(result)
	return err
}

func (ms *MongoSession) FindAll(name string, query, result any) error {
	return ms.FindAllContext(context.Background(), name, query, result)
}

func (ms *MongoSession) FindAllContext(ctx context.Context, name string, query, result any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).All(result)
}

func (ms *MongoSession) FindByLimitAndSkip(name string, query, result any, limit, skip int64) error {
	return ms.FindByLimitAndSkipContext(context.Background(), name, query, result, limit, skip)
}

func (ms *MongoSession) FindByLimitAndSkipContext(ctx context.Context, name string, query, result any, limit, skip int64) error {
	if limit <= 0 || skip < 0 {
		return ErrorLimit
	}

	err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Limit(limit).Skip(skip).All(result)
	return err
}

func (ms *MongoSession) FindCount(name string, query any) (int64, error) {
	return ms.FindCountContext(context.Background(), name, query)
}

func (ms *MongoSession) FindCountContext(ctx context.Context, name string, query any) (int64, error) {
	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Count(query)
}

func (ms *MongoSession) FindSortByLimitAndSkip(name string, query any, sorter, result any, limit, skip int64) error {
	return ms.FindSortByLimitAndSkipContext(context.Background(), name, query, sorter, result, limit, skip)
}

func (ms *MongoSession) FindSortByLimitAndSkipContext(ctx context.Context, name string, query any, sorter, result any, limit, skip int64) error {
	if limit < 0 || skip < 0 {
		return ErrorLimit
	}

	if limit == 0 {
		return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Sort(sorter).All(result)
	} else {
		return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Sort(sorter).Limit(limit).Skip(skip).All(result)
	}
}

func (ms *MongoSession) FindWithAggregation(name string, pipeline any, result any) error {
	return ms.FindWithAggregationContext(context.Background(), name, pipeline, result)
}

func (ms *MongoSession) FindWithAggregationContext(ctx context.Context, name string, pipeline any, result any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(nil).Pipe(pipeline, result)
}

// Remove deletes documents
func (ms *MongoSession) Remove(name string, query any, multi bool) error {
	return ms.RemoveContext(context.Background(), name, query, multi)
}

func (ms *MongoSession) RemoveContext(ctx context.Context, name string, query any, multi bool) error {
	if multi {
		return ms.session.DB(ms.dbName).C(name).WithContext(ctx).RemoveAll(query)
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Remove(query)
}

// RemoveById deletes document by ID
func (ms *MongoSession) RemoveById(name string, id any) error {
	return ms.RemoveByIdContext(context.Background(), name, id)
}

func (ms *MongoSession) RemoveByIdContext(ctx context.Context, name string, id any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).RemoveID(id)
}

// Insert inserts a document
func (ms *MongoSession) Insert(name string, doc any) error {
	return ms.InsertContext(context.Background(), name, doc)
}

func (ms *MongoSession) InsertContext(ctx context.Context, name string, doc any) error {
	err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).Insert(doc)
	return err
}

func (ms *MongoSession) InsertAll(name string, docs ...any) error {
	return ms.InsertAllContext(context.Background(), name, docs...)
}

func (ms *MongoSession) InsertAllContext(ctx context.Context, name string, docs ...any) error {
	err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).InsertAll(docs...)
	return err
}

// Update updates documents
func (ms *MongoSession) Update(name string, query any, update any, multi bool) error {
	return ms.UpdateContext(context.Background(), name, query, update, multi)
}

func (ms *MongoSession) UpdateContext(ctx context.Context, name string, query any, update any, multi bool) error {
	value := make(bson.M)
	value["$set"] = update
	if multi {
		_, err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).UpdateAll(query, value)
		return err
	}
	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Update(query, value)
}

// UpdateById updates document by ID
func (ms *MongoSession) UpdateById(name string, id any, update any) error {
	return ms.UpdateByIdContext(context.Background(), name, id, update)
}

func (ms *MongoSession) UpdateByIdContext(ctx context.Context, name string, id any, update any) error {
	value := make(bson.M)
	value["$set"] = update

	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).UpdateID(id, value)
}

// UpdateRaw supports MongoDB native update operations, $set, $inc ...
func (ms *MongoSession) UpdateRaw(name string, query any, update any, multi bool) error {
	return ms.UpdateRawContext(context.Background(), name, query, update, multi)
}

func (ms *MongoSession) UpdateRawContext(ctx context.Context, name string, query any, update any, multi bool) error {
	if multi {
		_, err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).UpdateAll(query, update, true)
		return err
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Update(query, update, true)
}

// GetNextSequence generates Int32 type auto-increment ID
func (ms *MongoSession) GetNextSequence(name string) (int32, error) {
	return ms.GetNextSequenceContext(context.Background(), name)
}

func (ms *MongoSession) GetNextSequenceContext(ctx context.Context, name string) (int32, error) {
	filter := bson.M{"_id": name}
	//update := bson.D{{"$inc", bson.M{"seq": 1}}}
	update := bson.M{"$inc": bson.M{"seq": 1}}

	seq, err := ms.session.DB(ms.dbName).C("tb_seq_counters").WithContext(ctx).FindAndAutoInc(name, filter, update)
	if err != nil {
		return -1, err
	}

	return seq, nil
}

// FindWithSelect supports field selection
func (ms *MongoSession) FindWithSelect(name string, query, selection, result any, limit int64) error {
	return ms.FindWithSelectContext(context.Background(), name, query, selection, result, limit)
}

func (ms *MongoSession) FindWithSelectContext(ctx context.Context, name string, query, selection, result any, limit int64) error {
	if limit <= 1 {
		err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Select(selection).One(result)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return ErrNotFound
			}
			return err
		}
		return nil
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Select(selection).Limit(limit).All(result)
}

// Select No Limit
func (ms *MongoSession) FindSelect(name string, query, selection, result any) error {
	return ms.FindSelectContext(context.Background(), name, query, selection, result)
}

func (ms *MongoSession) FindSelectContext(ctx context.Context, name string, query, selection, result any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Select(selection).All(result)
}

// FindWithMultiple performs comprehensive query, supports query, selection, sorter, limit, skip
func (ms *MongoSession) FindWithMultiple(name string, query, selection, sorter, result any, limit, skip int64) error {
	return ms.FindWithMultipleContext(context.Background(), name, query, selection, sorter, result, limit, skip)
}

func (ms *MongoSession) FindWithMultipleContext(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error {
	if limit < 0 || skip < 0 {
		return ErrorLimit
	}

	if limit == 1 {
		return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Select(selection).Sort(sorter).One(result)
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Select(selection).Sort(sorter).Limit(limit).Skip(skip).All(result)
}

func (ms *MongoSession) FindWithDistinct(name, distinct string, query any) ([]any, error) {
	return ms.FindWithDistinctContext(context.Background(), name, distinct, query)
}

func (ms *MongoSession) FindWithDistinctContext(ctx context.Context, name, distinct string, query any) ([]any, error) {
	result, err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).Find(query).Distinct(distinct)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Drop drops the collection directly
func (ms *MongoSession) Drop(name string) error {
	return ms.DropContext(context.Background(), name)
}

func (ms *MongoSession) DropContext(ctx context.Context, name string) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(ctx).Drop()
}
