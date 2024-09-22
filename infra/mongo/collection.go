// author: adaegis
// time: 2023-12-01

package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Collection struct {
	collection *mongo.Collection
}

// Find
func (c *Collection) Find(filter interface{}) *Session {
	return &Session{filter: filter, collection: c.collection}
}

// Select
func (c *Collection) Select(projection interface{}) *Session {
	return &Session{project: projection, collection: c.collection}
}

// Insert
func (c *Collection) Insert(document interface{}) error {
	var err error
	if _, err = c.collection.InsertOne(context.TODO(), document); err != nil {
		return err
	}
	return nil
}

// InsertWithResult
func (c *Collection) InsertWithResult(document interface{}) (result *mongo.InsertOneResult, err error) {
	result, err = c.collection.InsertOne(context.TODO(), document)
	return
}

// InsertAll
func (c *Collection) InsertAll(documents ...interface{}) error {
	var err error
	if _, err = c.collection.InsertMany(context.TODO(), documents); err != nil {
		return err
	}
	return nil
}

// InsertAllWithResult
func (c *Collection) InsertAllWithResult(documents []interface{}) (result *mongo.InsertManyResult, err error) {
	result, err = c.collection.InsertMany(context.TODO(), documents)
	return
}

// Update
func (c *Collection) Update(selector interface{}, update interface{}, upsert ...bool) error {
	if selector == nil {
		selector = bson.D{}
	}

	var err error

	opt := options.Update()
	for _, arg := range upsert {
		if arg {
			opt.SetUpsert(arg)
		}
	}

	if _, err = c.collection.UpdateOne(context.TODO(), selector, update, opt); err != nil {
		return err
	}
	return nil
}

// UpdateWithResult
func (c *Collection) UpdateWithResult(selector interface{}, update interface{}, upsert ...bool) (result *mongo.UpdateResult, err error) {
	if selector == nil {
		selector = bson.D{}
	}

	opt := options.Update()
	for _, arg := range upsert {
		if arg {
			opt.SetUpsert(arg)
		}
	}

	result, err = c.collection.UpdateOne(context.TODO(), selector, update, opt)
	return
}

// UpdateID
func (c *Collection) UpdateID(id interface{}, update interface{}) error {
	return c.Update(bson.M{"_id": id}, update)
}

// UpdateAll
func (c *Collection) UpdateAll(selector interface{}, update interface{}, upsert ...bool) (*mongo.UpdateResult, error) {
	if selector == nil {
		selector = bson.D{}
	}

	var err error

	opt := options.Update()
	for _, arg := range upsert {
		if arg {
			opt.SetUpsert(arg)
		}
	}

	var updateResult *mongo.UpdateResult
	if updateResult, err = c.collection.UpdateMany(context.TODO(), selector, update, opt); err != nil {
		return updateResult, err
	}
	return updateResult, nil
}

// Remove
func (c *Collection) Remove(selector interface{}) error {
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
func (c *Collection) RemoveID(id interface{}) error {
	return c.Remove(bson.M{"_id": id})
}

// RemoveAll
func (c *Collection) RemoveAll(selector interface{}) error {
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
func (c *Collection) Count(selector interface{}) (int64, error) {
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
func (c *Collection) FindAndAutoInc(name string, filter, update interface{}) (int32, error) {
	opt := options.FindOneAndUpdateOptions{}
	opt.SetUpsert(true)
	opt.SetReturnDocument(options.After)

	result := c.collection.FindOneAndUpdate(context.TODO(), filter, update, &opt)
	if result.Err() != nil && result.Err() != mongo.ErrNoDocuments {
		return -1, result.Err()
	}

	data, err := result.DecodeBytes()
	if err != nil {
		return -1, err
	}

	type seqRecord struct {
		ID  string `bson:"_id"`
		Seq int32  `bson:"seq"`
	}
	var doc seqRecord
	err = bson.Unmarshal(data, &doc)
	if err != nil {
		return -1, err
	}

	return doc.Seq, nil
}
