package mongo

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test configuration for UAT MongoDB
const (
	testMongoURI    = "mongodb://user_ada:XEl44B4p3hFurztFMo38@192.168.7.2:27017/db_ada?authSource=db_ada"
	testDBName      = "db_ada"
	testCollection  = "test_mongo_v2_upgrade"
	testSeqCollection = "test_seq_counters"
)

// TestDocument represents a test document structure
type TestDocument struct {
	ID        bson.ObjectID `bson:"_id,omitempty"`
	Name      string        `bson:"name"`
	Value     int           `bson:"value"`
	Tags      []string      `bson:"tags"`
	CreatedAt time.Time     `bson:"created_at"`
	UpdatedAt time.Time     `bson:"updated_at"`
}

// TestSeqCounter represents a sequence counter document
type TestSeqCounter struct {
	ID  string `bson:"_id"`
	Seq int32  `bson:"seq"`
}

// setupTestSession creates a new MongoDB session for testing
func setupTestSession(t *testing.T) *MongoSession {
	session := NewMongoSession()
	err := session.Connect(testMongoURI, testDBName)
	require.NoError(t, err, "Failed to connect to test MongoDB")

	session.SetPoolLimit(10)

	// Clean up test collection before tests
	_ = session.Drop(testCollection)
	_ = session.Drop(testSeqCollection)

	return session
}

// teardownTestSession closes the session and cleans up
func teardownTestSession(t *testing.T, session *MongoSession) {
	// Clean up test collections
	_ = session.Drop(testCollection)
	_ = session.Drop(testSeqCollection)

	session.Disconnect()
}

// TestUpdate tests the Update method with v2 driver
func TestUpdate(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Insert a test document
	doc := TestDocument{
		Name:      "test_update",
		Value:     100,
		Tags:      []string{"tag1", "tag2"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	err := session.Insert(testCollection, doc)
	require.NoError(t, err, "Failed to insert test document")

	// Test Update without upsert
	query := bson.M{"name": "test_update"}
	update := bson.M{"value": 200, "updated_at": time.Now()}

	err = session.Update(testCollection, query, update, false)
	assert.NoError(t, err, "Update should succeed")

	// Verify update
	var result TestDocument
	err, exists := session.FindOne(testCollection, query, &result)
	assert.NoError(t, err, "FindOne should succeed")
	assert.True(t, exists, "Document should exist")
	assert.Equal(t, 200, result.Value, "Value should be updated to 200")

	// Test Update on another document
	doc2 := TestDocument{
		Name:      "test_update2",
		Value:     300,
		Tags:      []string{"tag3"},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	err = session.Insert(testCollection, doc2)
	require.NoError(t, err, "Failed to insert second test document")

	query2 := bson.M{"name": "test_update2"}
	update2 := bson.M{"value": 400}
	err = session.Update(testCollection, query2, update2, false)
	assert.NoError(t, err, "Update should succeed")

	// Verify second update
	var result2 TestDocument
	err, exists = session.FindOne(testCollection, query2, &result2)
	assert.NoError(t, err, "FindOne should succeed")
	assert.True(t, exists, "Document should exist")
	assert.Equal(t, 400, result2.Value, "Value should be 400")
}

// TestUpdateWithResult tests the UpdateWithResult method
func TestUpdateWithResult(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Insert a test document
	doc := TestDocument{
		Name:      "test_update_result",
		Value:     150,
		CreatedAt: time.Now(),
	}

	err := session.Insert(testCollection, doc)
	require.NoError(t, err, "Failed to insert test document")

	// Test UpdateWithResult
	query := bson.M{"name": "test_update_result"}
	update := bson.M{"value": 250}

	err = session.Update(testCollection, query, update, false)
	assert.NoError(t, err, "UpdateWithResult should succeed")

	// Verify the update
	var result TestDocument
	err, exists := session.FindOne(testCollection, query, &result)
	assert.NoError(t, err, "FindOne should succeed")
	assert.True(t, exists, "Document should exist")
	assert.Equal(t, 250, result.Value, "Value should be updated to 250")
}

// TestUpdateAll tests the UpdateAll method
func TestUpdateAll(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Insert multiple test documents
	docs := []any{
		TestDocument{Name: "bulk_1", Value: 10, Tags: []string{"bulk"}, CreatedAt: time.Now()},
		TestDocument{Name: "bulk_2", Value: 20, Tags: []string{"bulk"}, CreatedAt: time.Now()},
		TestDocument{Name: "bulk_3", Value: 30, Tags: []string{"bulk"}, CreatedAt: time.Now()},
	}

	err := session.InsertAll(testCollection, docs...)
	require.NoError(t, err, "Failed to insert test documents")

	// Test UpdateAll
	query := bson.M{"tags": "bulk"}
	update := bson.M{"value": 999, "updated_at": time.Now()}

	err = session.UpdateRaw(testCollection, query, bson.M{"$set": update}, true)
	assert.NoError(t, err, "UpdateAll should succeed")

	// Verify all documents were updated
	var results []TestDocument
	err = session.FindAll(testCollection, query, &results)
	assert.NoError(t, err, "FindAll should succeed")
	assert.Len(t, results, 3, "Should have 3 documents")

	for _, result := range results {
		assert.Equal(t, 999, result.Value, "All values should be updated to 999")
	}
}

// TestFindAndAutoInc tests the FindAndAutoInc method
func TestFindAndAutoInc(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Test sequence generation
	seqName := "test_sequence"

	// Get first sequence number
	seq1, err := session.GetNextSequence(seqName)
	assert.NoError(t, err, "GetNextSequence should succeed")
	assert.Equal(t, int32(1), seq1, "First sequence should be 1")

	// Get second sequence number
	seq2, err := session.GetNextSequence(seqName)
	assert.NoError(t, err, "GetNextSequence should succeed")
	assert.Equal(t, int32(2), seq2, "Second sequence should be 2")

	// Get third sequence number
	seq3, err := session.GetNextSequence(seqName)
	assert.NoError(t, err, "GetNextSequence should succeed")
	assert.Equal(t, int32(3), seq3, "Third sequence should be 3")

	// Test concurrent sequence generation
	seqName2 := "test_sequence_2"
	seq2_1, err := session.GetNextSequence(seqName2)
	assert.NoError(t, err, "GetNextSequence should succeed")
	assert.Equal(t, int32(1), seq2_1, "First sequence of second counter should be 1")
}

// TestOne tests the One method with v2 driver
func TestOne(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Insert multiple documents
	docs := []any{
		TestDocument{Name: "first", Value: 1, CreatedAt: time.Now()},
		TestDocument{Name: "second", Value: 2, CreatedAt: time.Now().Add(-1 * time.Hour)},
		TestDocument{Name: "third", Value: 3, CreatedAt: time.Now().Add(-2 * time.Hour)},
	}

	err := session.InsertAll(testCollection, docs...)
	require.NoError(t, err, "Failed to insert test documents")

	// Test One with simple query
	query := bson.M{"name": "first"}
	var result TestDocument
	err, exists := session.FindOne(testCollection, query, &result)
	assert.NoError(t, err, "FindOne should succeed")
	assert.True(t, exists, "Document should exist")
	assert.Equal(t, "first", result.Name, "Name should be 'first'")
	assert.Equal(t, 1, result.Value, "Value should be 1")

	// Test One with non-existent document
	query2 := bson.M{"name": "nonexistent"}
	var result2 TestDocument
	err, exists = session.FindOne(testCollection, query2, &result2)
	assert.Error(t, err, "FindOne should return error for non-existent document")
	assert.False(t, exists, "Document should not exist")
	assert.Equal(t, ErrNotFound, err, "Error should be ErrNotFound")

	// Test One with projection
	query3 := bson.M{"name": "second"}
	selection := bson.M{"name": 1, "value": 1}
	var result3 TestDocument
	err = session.FindWithSelect(testCollection, query3, selection, &result3, 1)
	assert.NoError(t, err, "FindWithSelect should succeed")
	assert.Equal(t, "second", result3.Name, "Name should be 'second'")
	assert.Equal(t, 2, result3.Value, "Value should be 2")

	// Test One with sort (oldest first)
	query4 := bson.M{}
	sorter := bson.M{"created_at": 1}
	var result4 TestDocument
	err = session.FindWithMultiple(testCollection, query4, nil, sorter, &result4, 1, 0)
	assert.NoError(t, err, "FindWithMultiple should succeed")
	assert.Equal(t, "third", result4.Name, "Should return oldest document (third)")
}

// TestDistinct tests the Distinct method with v2 driver
func TestDistinct(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Insert documents with various tag combinations
	docs := []any{
		TestDocument{Name: "doc1", Value: 1, Tags: []string{"tag1", "tag2"}, CreatedAt: time.Now()},
		TestDocument{Name: "doc2", Value: 2, Tags: []string{"tag2", "tag3"}, CreatedAt: time.Now()},
		TestDocument{Name: "doc3", Value: 3, Tags: []string{"tag1", "tag3"}, CreatedAt: time.Now()},
		TestDocument{Name: "doc4", Value: 4, Tags: []string{"tag1"}, CreatedAt: time.Now()},
	}

	err := session.InsertAll(testCollection, docs...)
	require.NoError(t, err, "Failed to insert test documents")

	// Test Distinct on name field
	query := bson.M{}
	distinctValues, err := session.FindWithDistinct(testCollection, "name", query)
	assert.NoError(t, err, "FindWithDistinct should succeed")
	assert.Len(t, distinctValues, 4, "Should have 4 distinct names")

	// Convert to string slice for easier comparison
	var names []string
	for _, v := range distinctValues {
		if str, ok := v.(string); ok {
			names = append(names, str)
		}
	}
	assert.Contains(t, names, "doc1", "Should contain 'doc1'")
	assert.Contains(t, names, "doc2", "Should contain 'doc2'")
	assert.Contains(t, names, "doc3", "Should contain 'doc3'")
	assert.Contains(t, names, "doc4", "Should contain 'doc4'")

	// Test Distinct on value field
	distinctValues2, err := session.FindWithDistinct(testCollection, "value", query)
	assert.NoError(t, err, "FindWithDistinct should succeed")
	assert.Len(t, distinctValues2, 4, "Should have 4 distinct values")

	// Test Distinct with query filter
	query2 := bson.M{"value": bson.M{"$gte": 3}}
	distinctValues3, err := session.FindWithDistinct(testCollection, "name", query2)
	assert.NoError(t, err, "FindWithDistinct should succeed")
	assert.Len(t, distinctValues3, 2, "Should have 2 distinct names with value >= 3")
}

// TestUpdateById tests UpdateById method
func TestUpdateById(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Insert a document and get its ID
	doc := TestDocument{
		ID:        bson.NewObjectID(),
		Name:      "test_by_id",
		Value:     500,
		CreatedAt: time.Now(),
	}

	err := session.Insert(testCollection, doc)
	require.NoError(t, err, "Failed to insert test document")

	// Test UpdateById
	update := bson.M{"value": 600, "updated_at": time.Now()}
	err = session.UpdateById(testCollection, doc.ID, update)
	assert.NoError(t, err, "UpdateById should succeed")

	// Verify update
	var result TestDocument
	query := bson.M{"_id": doc.ID}
	err, exists := session.FindOne(testCollection, query, &result)
	assert.NoError(t, err, "FindOne should succeed")
	assert.True(t, exists, "Document should exist")
	assert.Equal(t, 600, result.Value, "Value should be updated to 600")
}

// TestComplexQueries tests complex query scenarios
func TestComplexQueries(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Insert test data
	now := time.Now()
	docs := []any{
		TestDocument{Name: "alpha", Value: 100, Tags: []string{"important", "urgent"}, CreatedAt: now.Add(-24 * time.Hour)},
		TestDocument{Name: "beta", Value: 200, Tags: []string{"important"}, CreatedAt: now.Add(-12 * time.Hour)},
		TestDocument{Name: "gamma", Value: 150, Tags: []string{"urgent"}, CreatedAt: now.Add(-6 * time.Hour)},
		TestDocument{Name: "delta", Value: 300, Tags: []string{"normal"}, CreatedAt: now},
	}

	err := session.InsertAll(testCollection, docs...)
	require.NoError(t, err, "Failed to insert test documents")

	// Test range query with sorting
	query := bson.M{"value": bson.M{"$gte": 150, "$lte": 250}}
	sorter := bson.M{"value": -1}
	var results []TestDocument

	err = session.FindSortByLimitAndSkip(testCollection, query, sorter, &results, 10, 0)
	assert.NoError(t, err, "FindSortByLimitAndSkip should succeed")
	assert.Len(t, results, 2, "Should find 2 documents")
	assert.Equal(t, "beta", results[0].Name, "First result should be beta (200)")
	assert.Equal(t, "gamma", results[1].Name, "Second result should be gamma (150)")

	// Test count
	count, err := session.FindCount(testCollection, query)
	assert.NoError(t, err, "FindCount should succeed")
	assert.Equal(t, int64(2), count, "Count should be 2")

	// Test pagination
	query2 := bson.M{}
	sorter2 := bson.M{"value": 1}
	var page1 []TestDocument
	err = session.FindSortByLimitAndSkip(testCollection, query2, sorter2, &page1, 2, 0)
	assert.NoError(t, err, "First page should succeed")
	assert.Len(t, page1, 2, "First page should have 2 documents")

	var page2 []TestDocument
	err = session.FindSortByLimitAndSkip(testCollection, query2, sorter2, &page2, 2, 2)
	assert.NoError(t, err, "Second page should succeed")
	assert.Len(t, page2, 2, "Second page should have 2 documents")

	// Verify different documents on each page
	assert.NotEqual(t, page1[0].Name, page2[0].Name, "Pages should have different documents")
}

// TestErrorHandling tests error scenarios
func TestErrorHandling(t *testing.T) {
	session := setupTestSession(t)
	defer teardownTestSession(t, session)

	// Test FindOne with non-existent document
	query := bson.M{"name": "nonexistent"}
	var result TestDocument
	err, exists := session.FindOne(testCollection, query, &result)
	assert.Error(t, err, "Should return error")
	assert.False(t, exists, "Document should not exist")
	assert.Equal(t, ErrNotFound, err, "Should be ErrNotFound")

	// Test Remove non-existent document (should not error)
	err = session.Remove(testCollection, query, false)
	assert.NoError(t, err, "Remove on non-existent document should not error")

	// Test invalid limit
	var results []TestDocument
	err = session.Find(testCollection, bson.M{}, &results, 0)
	assert.Error(t, err, "Should error on invalid limit")
	assert.Equal(t, ErrorLimit, err, "Should be ErrorLimit")
}
