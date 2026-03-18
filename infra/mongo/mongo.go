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

func (ms *MongoSession) Connect(ctx context.Context, uri, db string) error {
	ms.session = New(uri)
	ms.dbName = db
	ms.session.SetDB(db)

	err := ms.session.ConnectContext(normalizeContext(ctx))
	if err != nil {
		return err
	}

	return nil
}

func (ms *MongoSession) Disconnect(ctx context.Context) {
	ms.session.m.Lock()
	ms.session.DisconnectContext(normalizeContext(ctx))
	ms.session.m.Unlock()
}

func (ms *MongoSession) SetPoolLimit(limit uint64) {
	ms.session.SetPoolLimit(limit)
}

// FindOne performs actual find one operation
func (ms *MongoSession) FindOne(ctx context.Context, name string, query, result any) (err error, exist bool) {
	exist = true
	err = ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).One(result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return ErrNotFound, false
		}
		return err, false
	}

	return err, exist
}

func (ms *MongoSession) Find(ctx context.Context, name string, query, result any, limit int64) error {
	if limit <= 0 {
		return ErrorLimit
	}

	err := ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Limit(limit).All(result)
	return err
}

func (ms *MongoSession) FindAll(ctx context.Context, name string, query, result any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).All(result)
}

func (ms *MongoSession) FindByLimitAndSkip(ctx context.Context, name string, query, result any, limit, skip int64) error {
	if limit <= 0 || skip < 0 {
		return ErrorLimit
	}

	err := ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Limit(limit).Skip(skip).All(result)
	return err
}

func (ms *MongoSession) FindCount(ctx context.Context, name string, query any) (int64, error) {
	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Count(query)
}

func (ms *MongoSession) FindSortByLimitAndSkip(ctx context.Context, name string, query any, sorter, result any, limit, skip int64) error {
	if limit < 0 || skip < 0 {
		return ErrorLimit
	}

	if limit == 0 {
		return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Sort(sorter).All(result)
	} else {
		return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Sort(sorter).Limit(limit).Skip(skip).All(result)
	}
}

func (ms *MongoSession) FindWithAggregation(ctx context.Context, name string, pipeline any, result any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(nil).Pipe(pipeline, result)
}

// Remove deletes documents
func (ms *MongoSession) Remove(ctx context.Context, name string, query any, multi bool) error {
	if multi {
		return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).RemoveAll(query)
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Remove(query)
}

// RemoveById deletes document by ID
func (ms *MongoSession) RemoveById(ctx context.Context, name string, id any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).RemoveID(id)
}

// Insert inserts a document
func (ms *MongoSession) Insert(ctx context.Context, name string, doc any) error {
	err := ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Insert(doc)
	return err
}

func (ms *MongoSession) InsertAll(ctx context.Context, name string, docs ...any) error {
	err := ms.session.DB(ms.dbName).C(name).WithContext(ctx).InsertAll(docs...)
	return err
}

// Update updates documents
func (ms *MongoSession) Update(ctx context.Context, name string, query any, update any, multi bool) error {
	value := make(bson.M)
	value["$set"] = update
	if multi {
		_, err := ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).UpdateAll(query, value)
		return err
	}
	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Update(query, value)
}

// UpdateById updates document by ID
func (ms *MongoSession) UpdateById(ctx context.Context, name string, id any, update any) error {
	value := make(bson.M)
	value["$set"] = update

	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).UpdateID(id, value)
}

// UpdateRaw supports MongoDB native update operations, $set, $inc ...
func (ms *MongoSession) UpdateRaw(ctx context.Context, name string, query any, update any, multi bool) error {
	if multi {
		_, err := ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).UpdateAll(query, update, true)
		return err
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Update(query, update, true)
}

// GetNextSequence generates Int32 type auto-increment ID
func (ms *MongoSession) GetNextSequence(ctx context.Context, name string) (int32, error) {
	filter := bson.M{"_id": name}
	//update := bson.D{{"$inc", bson.M{"seq": 1}}}
	update := bson.M{"$inc": bson.M{"seq": 1}}

	seq, err := ms.session.DB(ms.dbName).C("tb_seq_counters").WithContext(normalizeContext(ctx)).FindAndAutoInc(name, filter, update)
	if err != nil {
		return -1, err
	}

	return seq, nil
}

// FindWithSelect supports field selection
func (ms *MongoSession) FindWithSelect(ctx context.Context, name string, query, selection, result any, limit int64) error {
	if limit <= 1 {
		err := ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Select(selection).One(result)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return ErrNotFound
			}
			return err
		}
		return nil
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Select(selection).Limit(limit).All(result)
}

// Select No Limit
func (ms *MongoSession) FindSelect(ctx context.Context, name string, query, selection, result any) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Select(selection).All(result)
}

// FindWithMultiple performs comprehensive query, supports query, selection, sorter, limit, skip
func (ms *MongoSession) FindWithMultiple(ctx context.Context, name string, query, selection, sorter, result any, limit, skip int64) error {
	if limit < 0 || skip < 0 {
		return ErrorLimit
	}

	if limit == 1 {
		return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Select(selection).Sort(sorter).One(result)
	}

	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Select(selection).Sort(sorter).Limit(limit).Skip(skip).All(result)
}

func (ms *MongoSession) FindWithDistinct(ctx context.Context, name, distinct string, query any) ([]any, error) {
	result, err := ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Find(query).Distinct(distinct)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Drop drops the collection directly
func (ms *MongoSession) Drop(ctx context.Context, name string) error {
	return ms.session.DB(ms.dbName).C(name).WithContext(normalizeContext(ctx)).Drop()
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx != nil {
		return ctx
	}
	return context.Background()
}
