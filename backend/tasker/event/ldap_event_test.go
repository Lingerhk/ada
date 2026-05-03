package event

import "testing"

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
