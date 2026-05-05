package event

import (
	"ada/backend/cache"
	"ada/infra/ldap"
	"ada/infra/mongo"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

type LdapEvent struct {
	redisCli     *redis.Client
	mongoCli     mongo.DBAdaptor
	lookupValues func(domain, entryType string) ([]any, error)
}

func NewLdapEvent(redisCli *redis.Client) *LdapEvent {
	return &LdapEvent{redisCli: redisCli}
}

type ldapLookupRequest struct {
	CacheKey        string `json:"cache_key"`
	Template        string `json:"template"`
	CacheTTLSeconds int64  `json:"cache_ttl_seconds"`
	RequestedAt     int64  `json:"requested_at"`
}

func (l *LdapEvent) Process(msgChan, msgData string) {
	var req ldapLookupRequest
	if err := json.Unmarshal([]byte(msgData), &req); err != nil {
		logger.Warnf("invalid ldap lookup request from %s: %v", msgChan, err)
		return
	}
	if req.CacheKey == "" {
		logger.Warnf("invalid empty ldap lookup cache key from %s", msgChan)
		return
	}

	domain, entryType, ok := parseLDAPLookupCacheKey(req.CacheKey)
	if !ok {
		logger.Warnf("unsupported ldap lookup cache key:%s", req.CacheKey)
		return
	}
	if entryType == "" {
		logger.Debugf("skip ldap lookup for cache key without ldap-backed entry type:%s", req.CacheKey)
		return
	}

	lookupValues := l.searchLDAPValues
	if l.lookupValues != nil {
		lookupValues = l.lookupValues
	}
	values, err := lookupValues(domain, entryType)
	if err != nil {
		logger.Warnf("ldap lookup failed domain:%s type:%s err:%v", domain, entryType, err)
		return
	}
	if len(values) == 0 {
		logger.Debugf("ldap lookup returned empty domain:%s type:%s", domain, entryType)
		return
	}

	ttl := time.Duration(req.CacheTTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pipe := l.redisCli.TxPipeline()
	pipe.Del(ctx, req.CacheKey)
	pipe.SAdd(ctx, req.CacheKey, values...)
	pipe.Expire(ctx, req.CacheKey, ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		logger.Warnf("write ldap lookup cache failed key:%s err:%v", req.CacheKey, err)
		return
	}
	logger.Debugf("ldap lookup cache refreshed key:%s count:%d ttl:%s", req.CacheKey, len(values), ttl)
}

func parseLDAPLookupCacheKey(cacheKey string) (domain, entryType string, ok bool) {
	const prefix = "ada:engine:"
	if !strings.HasPrefix(cacheKey, prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(cacheKey, prefix), ":")
	if len(parts) != 2 {
		return "", "", false
	}

	domain = strings.ToLower(strings.TrimSpace(parts[0]))
	switch parts[1] {
	case "sensitive_users":
		entryType = "user"
	case "sensitive_groups":
		entryType = "group"
	case "sensitive_computers":
		entryType = "computer"
	case "honeypot_accounts":
		entryType = ""
	default:
		return "", "", false
	}
	if domain == "" {
		return "", "", false
	}
	return domain, entryType, true
}

func (l *LdapEvent) searchLDAPValues(domain, entryType string) ([]any, error) {
	rdx := cache.NewRdxCli(l.redisCli)
	account, err := rdx.GetLDAPAccount(domain)
	if err != nil {
		return nil, err
	}

	ldapSearch, err := ldap.NewSearch(account.Server, account.User, account.Password, account.DNS, "")
	if err != nil {
		return nil, err
	}
	defer ldapSearch.Close()

	return queryLDAPEntryValues(ldapSearch, entryType)
}

func queryLDAPEntryValues(ldapSearch *ldap.LDAPSearch, entryType string) ([]any, error) {
	switch entryType {
	case "user":
		return ldapAttributeValues(ldapSearch, "(&(objectCategory=person)(objectClass=user)(adminCount=1))", "sAMAccountName")
	case "computer":
		return ldapAttributeValues(ldapSearch, "(|(primarygroupid=516)(primarygroupid=521)(primarygroupid=512))", "sAMAccountName")
	case "group":
		return ldapSensitiveGroupValues(ldapSearch)
	default:
		return nil, fmt.Errorf("unsupported ldap entry type:%s", entryType)
	}
}

func ldapAttributeValues(ldapSearch *ldap.LDAPSearch, filter, attr string) ([]any, error) {
	result, err := ldapSearch.BasicSearch(filter, attr)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	var values []any
	for _, entry := range result.Entries {
		for _, value := range entry.GetAttributeValues(attr) {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := strings.ToLower(value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			values = append(values, value)
		}
	}
	return values, nil
}

func ldapSensitiveGroupValues(ldapSearch *ldap.LDAPSearch) ([]any, error) {
	sensitiveGroups := []string{
		"Domain Admins",
		"Enterprise Admins",
		"Schema Admins",
		"Domain Controllers",
		"Account Operators",
		"Server Operators",
		"Enterprise Read-only Domain Controllers",
		"Key Admins",
		"Enterprise Key Admins",
		"DnsAdmins",
		"Organization Management",
		"Terminal Server License Servers",
		"Backup Operators",
		"Print Operators",
		"Administrators",
		"Remote Desktop Users",
		"Cert Publishers",
	}

	seen := make(map[string]struct{})
	var values []any
	for _, groupName := range sensitiveGroups {
		filter := fmt.Sprintf("(&(objectClass=group)(CN=%s))", groupName)
		result, err := ldapSearch.BasicSearch(filter, "sAMAccountName")
		if err != nil {
			logger.Warnf("ldap sensitive group lookup failed group:%s err:%v", groupName, err)
			continue
		}
		for _, entry := range result.Entries {
			for _, value := range entry.GetAttributeValues("sAMAccountName") {
				value = strings.TrimSpace(value)
				if value == "" {
					continue
				}
				key := strings.ToLower(value)
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				values = append(values, value)
			}
		}
	}
	return values, nil
}
