package mongo

import (
	"context"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type Collection struct {
	collection *mongo.Collection
	ctx        context.Context
}

// Find
func (c *Collection) Find(filter any) *Session {
	return &Session{ctx: c.ctx, filter: filter, collection: c.collection}
}

// Select
func (c *Collection) Select(projection any) *Session {
	return &Session{ctx: c.ctx, project: projection, collection: c.collection}
}

// WithContext clones the collection handle with an operation context.
func (c *Collection) WithContext(ctx context.Context) *Collection {
	clone := *c
	clone.ctx = ctx
	return &clone
}

// Insert
func (c *Collection) Insert(document any) error {
	return c.InsertContext(c.opContext(), document)
}

// InsertContext inserts a document with the provided context.
func (c *Collection) InsertContext(ctx context.Context, document any) error {
	_, err := c.collection.InsertOne(ctx, document)
	return err
}

// InsertWithResult
func (c *Collection) InsertWithResult(document any) (result *mongo.InsertOneResult, err error) {
	return c.InsertWithResultContext(c.opContext(), document)
}

// InsertWithResultContext inserts a document and returns the driver result.
func (c *Collection) InsertWithResultContext(ctx context.Context, document any) (result *mongo.InsertOneResult, err error) {
	return c.collection.InsertOne(ctx, document)
}

// InsertAll
func (c *Collection) InsertAll(documents ...any) error {
	return c.InsertAllContext(c.opContext(), documents...)
}

// InsertAllContext inserts documents with the provided context.
func (c *Collection) InsertAllContext(ctx context.Context, documents ...any) error {
	_, err := c.collection.InsertMany(ctx, documents)
	return err
}

// InsertAllWithResult
func (c *Collection) InsertAllWithResult(documents []any) (result *mongo.InsertManyResult, err error) {
	return c.InsertAllWithResultContext(c.opContext(), documents)
}

// InsertAllWithResultContext inserts documents and returns the driver result.
func (c *Collection) InsertAllWithResultContext(ctx context.Context, documents []any) (result *mongo.InsertManyResult, err error) {
	return c.collection.InsertMany(ctx, documents)
}

// Update
func (c *Collection) Update(selector any, update any, upsert ...bool) error {
	_, err := c.UpdateWithResultContext(c.opContext(), selector, update, upsert...)
	return err
}

// UpdateContext updates a single document with the provided context.
func (c *Collection) UpdateContext(ctx context.Context, selector any, update any, upsert ...bool) error {
	_, err := c.UpdateWithResultContext(ctx, selector, update, upsert...)
	return err
}

// UpdateWithResult
func (c *Collection) UpdateWithResult(selector any, update any, upsert ...bool) (result *mongo.UpdateResult, err error) {
	return c.UpdateWithResultContext(c.opContext(), selector, update, upsert...)
}

// UpdateWithResultContext updates a single document and returns the driver result.
func (c *Collection) UpdateWithResultContext(ctx context.Context, selector any, update any, upsert ...bool) (result *mongo.UpdateResult, err error) {
	if selector == nil {
		selector = bson.D{}
	}

	opt := options.UpdateOne()
	for _, arg := range upsert {
		if arg {
			opt = opt.SetUpsert(arg)
		}
	}

	return c.collection.UpdateOne(ctx, selector, update, opt)
}

// UpdateID
func (c *Collection) UpdateID(id any, update any) error {
	return c.Update(bson.M{"_id": id}, update)
}

// UpdateAll
func (c *Collection) UpdateAll(selector any, update any, upsert ...bool) (*mongo.UpdateResult, error) {
	return c.UpdateAllContext(c.opContext(), selector, update, upsert...)
}

// UpdateAllContext updates multiple documents with the provided context.
func (c *Collection) UpdateAllContext(ctx context.Context, selector any, update any, upsert ...bool) (*mongo.UpdateResult, error) {
	if selector == nil {
		selector = bson.D{}
	}

	opt := options.UpdateMany()
	for _, arg := range upsert {
		if arg {
			opt = opt.SetUpsert(arg)
		}
	}

	return c.collection.UpdateMany(ctx, selector, update, opt)
}

// Remove
func (c *Collection) Remove(selector any) error {
	return c.RemoveContext(c.opContext(), selector)
}

// RemoveContext deletes a single document with the provided context.
func (c *Collection) RemoveContext(ctx context.Context, selector any) error {
	if selector == nil {
		selector = bson.D{}
	}
	_, err := c.collection.DeleteOne(ctx, selector)
	return err
}

// RemoveID
func (c *Collection) RemoveID(id any) error {
	return c.Remove(bson.M{"_id": id})
}

// RemoveAll
func (c *Collection) RemoveAll(selector any) error {
	return c.RemoveAllContext(c.opContext(), selector)
}

// RemoveAllContext deletes multiple documents with the provided context.
func (c *Collection) RemoveAllContext(ctx context.Context, selector any) error {
	if selector == nil {
		selector = bson.D{}
	}
	_, err := c.collection.DeleteMany(ctx, selector)
	return err
}

// Count
func (c *Collection) Count(selector any) (int64, error) {
	return c.CountContext(c.opContext(), selector)
}

// CountContext counts documents with the provided context.
func (c *Collection) CountContext(ctx context.Context, selector any) (int64, error) {
	if selector == nil {
		selector = bson.D{}
	}
	return c.collection.CountDocuments(ctx, selector)
}

// Drop
func (c *Collection) Drop() error {
	return c.DropContext(c.opContext())
}

// DropContext drops the collection with the provided context.
func (c *Collection) DropContext(ctx context.Context) error {
	return c.collection.Drop(ctx)
}

// FindAndAutoInc
func (c *Collection) FindAndAutoInc(name string, filter, update any) (int32, error) {
	return c.FindAndAutoIncContext(c.opContext(), name, filter, update)
}

// FindAndAutoIncContext increments and returns the sequence with the provided context.
func (c *Collection) FindAndAutoIncContext(ctx context.Context, name string, filter, update any) (int32, error) {
	opt := options.FindOneAndUpdate().
		SetUpsert(true).
		SetReturnDocument(options.After)

	result := c.collection.FindOneAndUpdate(ctx, filter, update, opt)
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

func (c *Collection) opContext() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return context.Background()
}
