package event

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestParseLDAPLookupCacheKey(t *testing.T) {
	domain, entryType, ok := parseLDAPLookupCacheKey("ada:engine:Example.COM:sensitive_users")
	if !ok || domain != "example.com" || entryType != "user" {
		t.Fatalf("unexpected sensitive user key parse: domain=%s type=%s ok=%v", domain, entryType, ok)
	}

	domain, entryType, ok = parseLDAPLookupCacheKey("ada:engine:example.com:honeypot_accounts")
	if !ok || domain != "example.com" || entryType != "" {
		t.Fatalf("unexpected honeypot key parse: domain=%s type=%s ok=%v", domain, entryType, ok)
	}

	if _, _, ok := parseLDAPLookupCacheKey("ada:engine:example.com:unknown"); ok {
		t.Fatalf("expected unknown lookup key type to be rejected")
	}
}

func TestLdapEventProcessRefreshesCache(t *testing.T) {
	srv := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	defer rdb.Close()

	const key = "ada:engine:example.com:sensitive_users"
	called := false
	le := NewLdapEvent(rdb)
	le.lookupValues = func(domain, entryType string) ([]any, error) {
		called = true
		if domain != "example.com" || entryType != "user" {
			t.Fatalf("unexpected lookup args: domain=%s entryType=%s", domain, entryType)
		}
		return []any{"Administrator", "vagrant", "Administrator"}, nil
	}

	le.Process("test", `{"cache_key":"`+key+`","cache_ttl_seconds":60,"requested_at":1}`)
	if !called {
		t.Fatalf("expected LDAP lookup to be called")
	}

	ctx := context.Background()
	members, err := rdb.SMembers(ctx, key).Result()
	if err != nil {
		t.Fatalf("smembers failed: %v", err)
	}
	slices.Sort(members)
	if got, want := members, []string{"Administrator", "vagrant"}; !slices.Equal(got, want) {
		t.Fatalf("unexpected cache members: got=%v want=%v", got, want)
	}

	ttl, err := rdb.TTL(ctx, key).Result()
	if err != nil {
		t.Fatalf("ttl failed: %v", err)
	}
	if ttl <= 0 || ttl > time.Minute {
		t.Fatalf("unexpected cache ttl: %s", ttl)
	}
}
