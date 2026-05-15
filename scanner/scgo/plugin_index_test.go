package scgo

import (
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestMergePluginDocPreservesConfig(t *testing.T) {
	defaultDoc := map[string]any{
		"_id":       int32(10001),
		"name":      "weakpwd",
		"enable":    int32(1),
		"meta_data": map[string]any{"password": []string{"default"}},
		"desc":      "new desc",
	}
	existing := map[string]any{
		"_id":       int32(10001),
		"enable":    int32(0),
		"meta_data": bson.M{"password": bson.A{"custom"}},
		"desc":      "old desc",
	}

	got := mergePluginDoc(defaultDoc, existing, true)
	if got["enable"] != int32(0) {
		t.Fatalf("enable = %v, want existing value 0", got["enable"])
	}
	md, ok := got["meta_data"].(bson.M)
	if !ok {
		t.Fatalf("meta_data type = %T, want bson.M", got["meta_data"])
	}
	passwords, ok := md["password"].(bson.A)
	if !ok || len(passwords) != 1 || passwords[0] != "custom" {
		t.Fatalf("password metadata = %#v, want existing custom value", md["password"])
	}
	if got["desc"] != "new desc" {
		t.Fatalf("desc = %v, want package metadata refresh", got["desc"])
	}
}

func TestMergePluginListPreservesExistingConfig(t *testing.T) {
	defaultPlugins := []map[string]any{
		{"_id": int32(1), "enable": int32(1), "meta_data": map[string]any{"k": "default"}, "display": "new"},
		{"_id": int32(2), "enable": int32(1), "meta_data": map[string]any{"k": "second"}},
	}
	existingPlugins := bson.A{
		bson.M{"_id": int32(1), "enable": int32(0), "meta_data": bson.M{"k": "custom"}, "display": "old"},
	}

	got := mergePluginList(defaultPlugins, existingPlugins, true)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0]["enable"] != int32(0) {
		t.Fatalf("first enable = %v, want existing value 0", got[0]["enable"])
	}
	md, ok := got[0]["meta_data"].(bson.M)
	if !ok || md["k"] != "custom" {
		t.Fatalf("first meta_data = %#v, want existing custom value", got[0]["meta_data"])
	}
	if got[0]["display"] != "new" {
		t.Fatalf("first display = %v, want package metadata refresh", got[0]["display"])
	}
	if got[1]["enable"] != int32(1) {
		t.Fatalf("second enable = %v, want package default", got[1]["enable"])
	}
}
