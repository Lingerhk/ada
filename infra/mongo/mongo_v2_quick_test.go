package mongo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Quick smoke tests for MongoDB v2 driver upgrade
// These tests verify the 5 modified methods work correctly

const (
	quickTestURI        = "mongodb://user_ada:XEl44B4p3hFurztFMo38@192.168.7.2:27017/db_ada?authSource=db_ada"
	quickTestDB         = "db_ada"
	quickTestCollection = "test_quick_v2"
)

type QuickTestDoc struct {
	ID    bson.ObjectID `bson:"_id,omitempty"`
	Name  string        `bson:"name"`
	Value int           `bson:"value"`
	Time  time.Time     `bson:"time"`
}

func setupQuickTest(t *testing.T) *MongoSession {
	session := NewMongoSession()
	err := session.Connect(context.Background(), quickTestURI, quickTestDB)
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}

	// Clean up
	_ = session.Drop(context.Background(), quickTestCollection)
	_ = session.Drop(context.Background(), "tb_seq_counters")

	return session
}

func cleanupQuickTest(t *testing.T, session *MongoSession) {
	_ = session.Drop(context.Background(), quickTestCollection)
	_ = session.Drop(context.Background(), "tb_seq_counters")
	session.Disconnect(context.Background())
}

// Test 1: Update method (modified in collection.go:54-73)
func TestQuick_Update(t *testing.T) {
	session := setupQuickTest(t)
	defer cleanupQuickTest(t, session)

	fmt.Println("\n=== Testing Update Method ===")

	// Insert a document
	doc := QuickTestDoc{
		Name:  "test1",
		Value: 100,
		Time:  time.Now(),
	}
	err := session.Insert(context.Background(), quickTestCollection, doc)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	fmt.Println("✓ Inserted document")

	// Update the document
	query := bson.M{"name": "test1"}
	update := bson.M{"value": 200}
	err = session.Update(context.Background(), quickTestCollection, query, update, false)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	fmt.Println("✓ Update executed")

	// Verify update
	var result QuickTestDoc
	err, exists := session.FindOne(context.Background(), quickTestCollection, query, &result)
	if err != nil {
		t.Fatalf("FindOne failed: %v", err)
	}
	if !exists {
		t.Fatal("Document not found after update")
	}
	if result.Value != 200 {
		t.Fatalf("Expected value 200, got %d", result.Value)
	}
	fmt.Printf("✓ Verified: Value updated to %d\n", result.Value)
}

// Test 2: UpdateAll method (modified in collection.go:97-117)
func TestQuick_UpdateAll(t *testing.T) {
	session := setupQuickTest(t)
	defer cleanupQuickTest(t, session)

	fmt.Println("\n=== Testing UpdateAll Method ===")

	// Insert multiple documents
	docs := []any{
		QuickTestDoc{Name: "bulk1", Value: 10, Time: time.Now()},
		QuickTestDoc{Name: "bulk2", Value: 20, Time: time.Now()},
		QuickTestDoc{Name: "bulk3", Value: 30, Time: time.Now()},
	}
	err := session.InsertAll(context.Background(), quickTestCollection, docs...)
	if err != nil {
		t.Fatalf("InsertAll failed: %v", err)
	}
	fmt.Println("✓ Inserted 3 documents")

	// Update all documents using UpdateRaw (which calls UpdateAll internally)
	query := bson.M{}
	update := bson.M{"$set": bson.M{"value": 999}}
	err = session.UpdateRaw(context.Background(), quickTestCollection, query, update, true)
	if err != nil {
		t.Fatalf("UpdateAll failed: %v", err)
	}
	fmt.Println("✓ UpdateAll executed")

	// Verify all documents were updated
	var results []QuickTestDoc
	err = session.FindAll(context.Background(), quickTestCollection, query, &results)
	if err != nil {
		t.Fatalf("FindAll failed: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("Expected 3 documents, got %d", len(results))
	}
	for i, result := range results {
		if result.Value != 999 {
			t.Fatalf("Document %d: expected value 999, got %d", i, result.Value)
		}
	}
	fmt.Println("✓ Verified: All 3 documents updated to 999")
}

// Test 3: FindAndAutoInc method (modified in collection.go:165-187)
func TestQuick_FindAndAutoInc(t *testing.T) {
	session := setupQuickTest(t)
	defer cleanupQuickTest(t, session)

	fmt.Println("\n=== Testing FindAndAutoInc Method ===")

	// Get sequence numbers
	seq1, err := session.GetNextSequence(context.Background(), "test_seq")
	if err != nil {
		t.Fatalf("GetNextSequence failed: %v", err)
	}
	if seq1 != 1 {
		t.Fatalf("Expected first sequence to be 1, got %d", seq1)
	}
	fmt.Printf("✓ First sequence: %d\n", seq1)

	seq2, err := session.GetNextSequence(context.Background(), "test_seq")
	if err != nil {
		t.Fatalf("GetNextSequence failed: %v", err)
	}
	if seq2 != 2 {
		t.Fatalf("Expected second sequence to be 2, got %d", seq2)
	}
	fmt.Printf("✓ Second sequence: %d\n", seq2)

	seq3, err := session.GetNextSequence(context.Background(), "test_seq")
	if err != nil {
		t.Fatalf("GetNextSequence failed: %v", err)
	}
	if seq3 != 3 {
		t.Fatalf("Expected third sequence to be 3, got %d", seq3)
	}
	fmt.Printf("✓ Third sequence: %d\n", seq3)
	fmt.Println("✓ Verified: Sequence auto-increment working correctly")
}

// Test 4: One method (modified in session.go:149-167)
func TestQuick_One(t *testing.T) {
	session := setupQuickTest(t)
	defer cleanupQuickTest(t, session)

	fmt.Println("\n=== Testing One Method ===")

	// Insert documents
	docs := []any{
		QuickTestDoc{Name: "first", Value: 1, Time: time.Now()},
		QuickTestDoc{Name: "second", Value: 2, Time: time.Now()},
	}
	err := session.InsertAll(context.Background(), quickTestCollection, docs...)
	if err != nil {
		t.Fatalf("InsertAll failed: %v", err)
	}
	fmt.Println("✓ Inserted 2 documents")

	// Test FindOne
	query := bson.M{"name": "first"}
	var result QuickTestDoc
	err, exists := session.FindOne(context.Background(), quickTestCollection, query, &result)
	if err != nil {
		t.Fatalf("FindOne failed: %v", err)
	}
	if !exists {
		t.Fatal("Document not found")
	}
	if result.Name != "first" || result.Value != 1 {
		t.Fatalf("Expected name='first' value=1, got name='%s' value=%d", result.Name, result.Value)
	}
	fmt.Printf("✓ FindOne returned: name=%s, value=%d\n", result.Name, result.Value)

	// Test non-existent document
	query2 := bson.M{"name": "nonexistent"}
	var result2 QuickTestDoc
	err, exists = session.FindOne(context.Background(), quickTestCollection, query2, &result2)
	if err != ErrNotFound {
		t.Fatalf("Expected ErrNotFound, got: %v", err)
	}
	if exists {
		t.Fatal("Document should not exist")
	}
	fmt.Println("✓ FindOne correctly returns ErrNotFound for non-existent document")
}

// Test 5: Distinct method (modified in session.go:276-293)
func TestQuick_Distinct(t *testing.T) {
	session := setupQuickTest(t)
	defer cleanupQuickTest(t, session)

	fmt.Println("\n=== Testing Distinct Method ===")

	// Insert documents with various names
	docs := []any{
		QuickTestDoc{Name: "alice", Value: 1, Time: time.Now()},
		QuickTestDoc{Name: "bob", Value: 2, Time: time.Now()},
		QuickTestDoc{Name: "alice", Value: 3, Time: time.Now()},
		QuickTestDoc{Name: "charlie", Value: 4, Time: time.Now()},
	}
	err := session.InsertAll(context.Background(), quickTestCollection, docs...)
	if err != nil {
		t.Fatalf("InsertAll failed: %v", err)
	}
	fmt.Println("✓ Inserted 4 documents (with duplicate names)")

	// Get distinct names
	query := bson.M{}
	distinctNames, err := session.FindWithDistinct(context.Background(), quickTestCollection, "name", query)
	if err != nil {
		t.Fatalf("FindWithDistinct failed: %v", err)
	}
	if len(distinctNames) != 3 {
		t.Fatalf("Expected 3 distinct names, got %d", len(distinctNames))
	}
	fmt.Printf("✓ Found %d distinct names: ", len(distinctNames))

	// Convert and print
	nameMap := make(map[string]bool)
	for _, v := range distinctNames {
		if str, ok := v.(string); ok {
			nameMap[str] = true
			fmt.Printf("%s ", str)
		}
	}
	fmt.Println()

	// Verify expected names
	if !nameMap["alice"] || !nameMap["bob"] || !nameMap["charlie"] {
		t.Fatal("Missing expected names in distinct result")
	}
	fmt.Println("✓ Verified: alice, bob, charlie found")
}

// Test 6: Complex workflow combining all methods
func TestQuick_ComplexWorkflow(t *testing.T) {
	session := setupQuickTest(t)
	defer cleanupQuickTest(t, session)

	fmt.Println("\n=== Testing Complex Workflow ===")

	// 1. Use FindAndAutoInc to get ID
	id, err := session.GetNextSequence(context.Background(), "workflow_seq")
	if err != nil {
		t.Fatalf("GetNextSequence failed: %v", err)
	}
	fmt.Printf("✓ Generated ID: %d\n", id)

	// 2. Insert document with generated ID
	doc := QuickTestDoc{
		Name:  fmt.Sprintf("doc_%d", id),
		Value: int(id * 100),
		Time:  time.Now(),
	}
	err = session.Insert(context.Background(), quickTestCollection, doc)
	if err != nil {
		t.Fatalf("Insert failed: %v", err)
	}
	fmt.Println("✓ Inserted document with generated ID")

	// 3. Use FindOne to retrieve
	query := bson.M{"name": doc.Name}
	var result QuickTestDoc
	err, exists := session.FindOne(context.Background(), quickTestCollection, query, &result)
	if err != nil {
		t.Fatalf("FindOne failed: %v", err)
	}
	if !exists {
		t.Fatal("Document not found")
	}
	fmt.Printf("✓ Retrieved document: value=%d\n", result.Value)

	// 4. Use Update to modify
	update := bson.M{"value": 999}
	err = session.Update(context.Background(), quickTestCollection, query, update, false)
	if err != nil {
		t.Fatalf("Update failed: %v", err)
	}
	fmt.Println("✓ Updated document value to 999")

	// 5. Use FindOne again to verify
	var result2 QuickTestDoc
	err, exists = session.FindOne(context.Background(), quickTestCollection, query, &result2)
	if err != nil {
		t.Fatalf("FindOne failed: %v", err)
	}
	if result2.Value != 999 {
		t.Fatalf("Expected value 999, got %d", result2.Value)
	}
	fmt.Printf("✓ Verified update: value=%d\n", result2.Value)

	// 6. Use Distinct to verify uniqueness
	distinctValues, err := session.FindWithDistinct(context.Background(), quickTestCollection, "value", bson.M{})
	if err != nil {
		t.Fatalf("FindWithDistinct failed: %v", err)
	}
	fmt.Printf("✓ Found %d distinct values\n", len(distinctValues))

	fmt.Println("✓ Complex workflow completed successfully!")
}
