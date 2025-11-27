package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Collection struct {
	collection *mongo.Collection
}

// Find
func (c *Collection) Find(filter any) *Session {
	return &Session{filter: filter, collection: c.collection}
}

// Select
func (c *Collection) Select(projection any) *Session {
	return &Session{project: projection, collection: c.collection}
}

// Insert
func (c *Collection) Insert(document any) error {
	var err error
	if _, err = c.collection.InsertOne(context.TODO(), document); err != nil {
		return err
	}
	return nil
}

// InsertWithResult
func (c *Collection) InsertWithResult(document any) (result *mongo.InsertOneResult, err error) {
	result, err = c.collection.InsertOne(context.TODO(), document)
	return
}

// InsertAll
func (c *Collection) InsertAll(documents ...any) error {
	var err error
	if _, err = c.collection.InsertMany(context.TODO(), documents); err != nil {
		return err
	}
	return nil
}

// InsertAllWithResult
func (c *Collection) InsertAllWithResult(documents []any) (result *mongo.InsertManyResult, err error) {
	result, err = c.collection.InsertMany(context.TODO(), documents)
	return
}

// Update
func (c *Collection) Update(selector any, update any, upsert ...bool) error {
	if selector == nil {
		selector = bson.D{}
	}

	var err error

	opt := options.UpdateOne()
	for _, arg := range upsert {
		if arg {
			opt = opt.SetUpsert(arg)
		}
	}

	if _, err = c.collection.UpdateOne(context.TODO(), selector, update, opt); err != nil {
		return err
	}
	return nil
}

// UpdateWithResult
func (c *Collection) UpdateWithResult(selector any, update any, upsert ...bool) (result *mongo.UpdateResult, err error) {
	if selector == nil {
		selector = bson.D{}
	}

	opt := options.UpdateOne()
	for _, arg := range upsert {
		if arg {
			opt = opt.SetUpsert(arg)
		}
	}

	result, err = c.collection.UpdateOne(context.TODO(), selector, update, opt)
	return
}

// UpdateID
func (c *Collection) UpdateID(id any, update any) error {
	return c.Update(bson.M{"_id": id}, update)
}

// UpdateAll
func (c *Collection) UpdateAll(selector any, update any, upsert ...bool) (*mongo.UpdateResult, error) {
	if selector == nil {
		selector = bson.D{}
	}

	var err error

	opt := options.UpdateMany()
	for _, arg := range upsert {
		if arg {
			opt = opt.SetUpsert(arg)
		}
	}

	var updateResult *mongo.UpdateResult
	if updateResult, err = c.collection.UpdateMany(context.TODO(), selector, update, opt); err != nil {
		return updateResult, err
	}
	return updateResult, nil
}

// Remove
func (c *Collection) Remove(selector any) error {
	if selector == nil {
		selector = bson.D{}
	}
	var err error
	if _, err = c.collection.DeleteOne(context.TODO(), selector); err != nil {
		return err
	}
	return nil
}

// RemoveID
func (c *Collection) RemoveID(id any) error {
	return c.Remove(bson.M{"_id": id})
}

// RemoveAll
func (c *Collection) RemoveAll(selector any) error {
	if selector == nil {
		selector = bson.D{}
	}
	var err error

	if _, err = c.collection.DeleteMany(context.TODO(), selector); err != nil {
		return err
	}
	return nil
}

// Count
func (c *Collection) Count(selector any) (int64, error) {
	if selector == nil {
		selector = bson.D{}
	}
	var err error
	var count int64
	count, err = c.collection.CountDocuments(context.TODO(), selector)
	return count, err
}

// Drop
func (c *Collection) Drop() error {
	return c.collection.Drop(context.TODO())
}

// FindAndAutoInc
func (c *Collection) FindAndAutoInc(name string, filter, update any) (int32, error) {
	opt := options.FindOneAndUpdate().
		SetUpsert(true).
		SetReturnDocument(options.After)

	result := c.collection.FindOneAndUpdate(context.TODO(), filter, update, opt)
	if result.Err() != nil && result.Err() != mongo.ErrNoDocuments {
		return -1, result.Err()
	}

	type seqRecord struct {
		ID  string `bson:"_id"`
		Seq int32  `bson:"seq"`
	}
	var doc seqRecord
	err := result.Decode(&doc)
	if err != nil {
		return -1, err
	}

	return doc.Seq, nil
}
