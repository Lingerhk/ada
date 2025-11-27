package mongo

import (
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

func (ms *MongoSession) Connect(uri, db string) error {

	ms.session = New(uri)
	ms.dbName = db
	ms.session.SetDB(db)

	err := ms.session.Connect()
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
	exist = true
	err = ms.session.DB(ms.dbName).C(name).Find(query).One(result)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			return ErrNotFound, false
		}
		return err, false
	}

	return err, exist
}

func (ms *MongoSession) Find(name string, query, result any, limit int64) error {
	if limit <= 0 {
		return ErrorLimit
	}

	err := ms.session.DB(ms.dbName).C(name).Find(query).Limit(limit).All(result)
	return err
}

func (ms *MongoSession) FindAll(name string, query, result any) error {
	return ms.session.DB(ms.dbName).C(name).Find(query).All(result)
}

func (ms *MongoSession) FindByLimitAndSkip(name string, query, result any, limit, skip int64) error {
	if limit <= 0 || skip < 0 {
		return ErrorLimit
	}

	err := ms.session.DB(ms.dbName).C(name).Find(query).Limit(limit).Skip(skip).All(result)
	return err
}

func (ms *MongoSession) FindCount(name string, query any) (int64, error) {
	return ms.session.DB(ms.dbName).C(name).Count(query)
}

func (ms *MongoSession) FindSortByLimitAndSkip(name string, query any, sorter, result any, limit, skip int64) error {
	if limit < 0 || skip < 0 {
		return ErrorLimit
	}

	if limit == 0 {
		return ms.session.DB(ms.dbName).C(name).Find(query).Sort(sorter).All(result)
	} else {
		return ms.session.DB(ms.dbName).C(name).Find(query).Sort(sorter).Limit(limit).Skip(skip).All(result)
	}
}

func (ms *MongoSession) FindWithAggregation(name string, pipeline any, result any) error {
	return ms.session.DB(ms.dbName).C(name).Find(nil).Pipe(pipeline, result)
}

// Remove deletes documents
func (ms *MongoSession) Remove(name string, query any, multi bool) error {
	if multi {
		return ms.session.DB(ms.dbName).C(name).RemoveAll(query)
	}

	return ms.session.DB(ms.dbName).C(name).Remove(query)
}

// RemoveById deletes document by ID
func (ms *MongoSession) RemoveById(name string, id any) error {
	return ms.session.DB(ms.dbName).C(name).RemoveID(id)
}

// Insert inserts a document
func (ms *MongoSession) Insert(name string, doc any) error {
	err := ms.session.DB(ms.dbName).C(name).Insert(doc)
	return err
}

func (ms *MongoSession) InsertAll(name string, docs ...any) error {
	err := ms.session.DB(ms.dbName).C(name).InsertAll(docs...)

	return err
}

// Update updates documents
func (ms *MongoSession) Update(name string, query any, update any, multi bool) error {
	value := make(bson.M)
	value["$set"] = update
	if multi {
		_, err := ms.session.DB(ms.dbName).C(name).UpdateAll(query, value)
		return err
	}
	return ms.session.DB(ms.dbName).C(name).Update(query, value)
}

// UpdateById updates document by ID
func (ms *MongoSession) UpdateById(name string, id any, update any) error {
	value := make(bson.M)
	value["$set"] = update

	return ms.session.DB(ms.dbName).C(name).UpdateID(id, value)
}

// UpdateRaw supports MongoDB native update operations, $set, $inc ...
func (ms *MongoSession) UpdateRaw(name string, query any, update any, multi bool) error {
	if multi {
		_, err := ms.session.DB(ms.dbName).C(name).UpdateAll(query, update, true)
		return err
	}

	return ms.session.DB(ms.dbName).C(name).Update(query, update, true)
}

// GetNextSequence generates Int32 type auto-increment ID
func (ms *MongoSession) GetNextSequence(name string) (int32, error) {
	filter := bson.M{"_id": name}
	//update := bson.D{{"$inc", bson.M{"seq": 1}}}
	update := bson.M{"$inc": bson.M{"seq": 1}}

	seq, err := ms.session.DB(ms.dbName).C("tb_seq_counters").FindAndAutoInc(name, filter, update)
	if err != nil {
		return -1, err
	}

	return seq, nil
}

// FindWithSelect supports field selection
func (ms *MongoSession) FindWithSelect(name string, query, selection, result any, limit int64) error {
	if limit <= 1 {
		err := ms.session.DB(ms.dbName).C(name).Find(query).Select(selection).One(result)
		if err != nil {
			if err == mongo.ErrNoDocuments {
				return ErrNotFound
			}
			return err
		}
		return nil
	}

	return ms.session.DB(ms.dbName).C(name).Find(query).Select(selection).Limit(limit).All(result)
}

// Select No Limit
func (ms *MongoSession) FindSelect(name string, query, selection, result any) error {

	return ms.session.DB(ms.dbName).C(name).Find(query).Select(selection).All(result)
}

// FindWithMultiple performs comprehensive query, supports query, selection, sorter, limit, skip
func (ms *MongoSession) FindWithMultiple(name string, query, selection, sorter, result any, limit, skip int64) error {
	if limit < 0 || skip < 0 {
		return ErrorLimit
	}

	if limit == 1 {
		return ms.session.DB(ms.dbName).C(name).Find(query).Select(selection).Sort(sorter).One(result)
	}

	return ms.session.DB(ms.dbName).C(name).Find(query).Select(selection).Sort(sorter).Limit(limit).Skip(skip).All(result)
}

func (ms *MongoSession) FindWithDistinct(name, distinct string, query any) ([]any, error) {
	result, err := ms.session.DB(ms.dbName).C(name).Find(query).Distinct(distinct)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Drop drops the collection directly
func (ms *MongoSession) Drop(name string) error {
	return ms.session.DB(ms.dbName).C(name).Drop()
}
