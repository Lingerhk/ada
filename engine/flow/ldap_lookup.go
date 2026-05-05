package flow

import (
	"ada/engine/common"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	logger "github.com/sirupsen/logrus"
)

type ldapLookupRequest struct {
	CacheKey        string `json:"cache_key"`
	Template        string `json:"template"`
	CacheTTLSeconds int64  `json:"cache_ttl_seconds"`
	RequestedAt     int64  `json:"requested_at"`
}

func getFieldLDAPVal(ctx context.Context, redisCli *redis.Client, field2 string, acts []flowActivity) []string {
	if redisCli == nil {
		return []string{}
	}

	cacheKey, ok := buildCacheLookupKey(field2, acts)
	if !ok {
		logger.Warnf("invalid ldap key template:%s", field2)
		return []string{}
	}

	items, err := redisCli.SMembers(ctx, cacheKey).Result()
	if err != nil {
		logger.Warnf("ldap cache lookup failed key:%s err:%v", cacheKey, err)
		return []string{}
	}
	if len(items) > 0 {
		return items
	}

	publishLDAPLookupMiss(ctx, redisCli, field2, cacheKey)
	return []string{}
}

func publishLDAPLookupMiss(ctx context.Context, redisCli *redis.Client, template, cacheKey string) {
	pendingKey := ldapPendingKey(cacheKey)
	req := ldapLookupRequest{
		CacheKey:        cacheKey,
		Template:        template,
		CacheTTLSeconds: common.LdapSearchCacheTTLSeconds,
		RequestedAt:     time.Now().Unix(),
	}
	payload, err := json.Marshal(req)
	if err != nil {
		logger.Warnf("marshal ldap lookup request failed key:%s err:%v", cacheKey, err)
		return
	}

	ok, err := redisCli.SetNX(ctx, pendingKey, payload, time.Duration(common.LdapSearchCacheTTLSeconds)*time.Second).Result()
	if err != nil {
		logger.Warnf("set ldap pending key failed key:%s err:%v", pendingKey, err)
		return
	}
	if !ok {
		return
	}

	if err := redisCli.Publish(ctx, common.LdapSearchPubsubChan, payload).Err(); err != nil {
		logger.Warnf("publish ldap lookup request failed key:%s err:%v", cacheKey, err)
		_ = redisCli.Del(ctx, pendingKey).Err()
	}
}

func ldapPendingKey(cacheKey string) string {
	return fmt.Sprintf("%s:%s", common.LdapSearchPendingPrefixKey, hashCacheKeyParts([]string{cacheKey}))
}
