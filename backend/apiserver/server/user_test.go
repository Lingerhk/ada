package server

import (
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func TestDescribeUserDecodeError(t *testing.T) {
	now := time.Now()

	t.Run("valid user docs", func(t *testing.T) {
		err := describeUserDecodeError([]bson.M{
			{
				"_id":           int32(1),
				"username":      "adaegis",
				"password":      "hash",
				"pass_strength": "low",
				"role":          "mgr",
				"priv":          int32(1),
				"mobile":        "12345678901",
				"email":         "admin@adaegis.net",
				"remark":        "default admin",
				"secret":        "",
				"mfa_status":    "disable",
				"avatar":        "",
				"pwd_update_tm": now,
				"department":    "Adaegis",
				"active_tm":     now,
				"create_tm":     now,
				"update_tm":     now,
			},
		})
		if err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
	})

	t.Run("invalid user id type", func(t *testing.T) {
		err := describeUserDecodeError([]bson.M{
			{
				"_id":       bson.NewObjectID(),
				"username":  "admin",
				"active_tm": now,
			},
		})
		if err == nil {
			t.Fatal("expected decode error, got nil")
		}
		if !strings.Contains(err.Error(), "username=admin") {
			t.Fatalf("expected username in error, got %v", err)
		}
		if !strings.Contains(err.Error(), "decode tb_user") {
			t.Fatalf("expected decode context in error, got %v", err)
		}
	})
}
