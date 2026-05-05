package flow

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	logger "github.com/sirupsen/logrus"
)

type fieldRef struct {
	idx   int64
	field string
}

func validateCacheTemplate(template string) bool {
	if !strings.HasPrefix(template, "key_") {
		return false
	}

	keyPattern, refs, ok := parseCacheTemplate(template)
	if !ok {
		return false
	}
	return strings.Count(keyPattern, "%s") == len(refs)
}

func parseCacheTemplate(template string) (string, []fieldRef, bool) {
	if !strings.HasPrefix(template, "key_") {
		return "", nil, false
	}

	keyExpr := strings.TrimPrefix(template, "key_")
	if !strings.Contains(template, "(") && !strings.Contains(template, ")") {
		return keyExpr, nil, true
	}

	parts := strings.SplitN(template, "(", 2)
	if len(parts) != 2 || !strings.HasSuffix(parts[1], ")") {
		return "", nil, false
	}

	keyExpr = strings.TrimPrefix(parts[0], "key_")
	paramExpr := strings.TrimSpace(strings.TrimSuffix(parts[1], ")"))
	if paramExpr == "" {
		return keyExpr, nil, strings.Count(keyExpr, "%s") == 0
	}

	var refs []fieldRef
	for _, param := range strings.Split(strings.ReplaceAll(paramExpr, " ", ""), ",") {
		idx, field := parseConditionKV(param)
		if idx < 0 || field == "" {
			return "", nil, false
		}
		refs = append(refs, fieldRef{idx: idx, field: field})
	}

	return keyExpr, refs, true
}

func extractCacheFieldRefs(template string) []fieldRef {
	_, refs, ok := parseCacheTemplate(template)
	if !ok {
		return nil
	}
	return refs
}

func buildCacheLookupKey(template string, acts []flowActivity) (string, bool) {
	keyExpr, refs, ok := parseCacheTemplate(template)
	if !ok {
		return "", false
	}
	if strings.Count(keyExpr, "%s") != len(refs) {
		return "", false
	}
	if len(refs) == 0 {
		return keyExpr, true
	}

	var paramVals []any
	for _, ref := range refs {
		if ref.idx < 0 || int(ref.idx) >= len(acts) {
			return "", false
		}
		fieldVal := normalizeCacheLookupValue(ref.field, getFieldVal(ref.field, acts[ref.idx]), acts)
		if fieldVal == "" {
			logger.Warnf("invalid cache lookup template(%s), field(%s) empty", template, ref.field)
			return "", false
		}
		paramVals = append(paramVals, fieldVal)
	}

	return fmt.Sprintf(keyExpr, paramVals...), true
}

func normalizeCacheLookupValue(field, value string, acts []flowActivity) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if field != "TargetDomainName" || value == "" || len(acts) == 0 {
		return value
	}

	hostname := strings.ToLower(strings.TrimSpace(acts[0].activityCache["field_Hostname"]))
	if hostname == "" {
		return value
	}
	return normalizeDomain(value, hostname)
}

func addCacheKeyFields(sigmaRuleFields map[string][]string, cacheKey map[string][]string) {
	for sid, specs := range cacheKey {
		for _, spec := range specs {
			field, _, ok := parseCacheKeyFieldSpec(spec)
			if !ok {
				logger.Warnf("ignore invalid cache_key field spec(%s) for sigma_id:%s", spec, sid)
				continue
			}
			sigmaRuleFields[sid] = append(sigmaRuleFields[sid], field)
		}
	}
}

func parseCacheKeyFieldSpec(spec string) (string, []string, bool) {
	parts := strings.Split(spec, "|")
	if len(parts) == 0 {
		return "", nil, false
	}

	field := strings.TrimSpace(strings.TrimPrefix(parts[0], "$."))
	if strings.HasPrefix(field, "$s") {
		_, parsed := parseConditionKV(field)
		field = parsed
	}
	if field == "" {
		return "", nil, false
	}

	var normalizers []string
	for _, item := range parts[1:] {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		switch item {
		case "lower", "trim", "domain", "ip":
			normalizers = append(normalizers, item)
		default:
			logger.Warnf("ignore invalid cache_key normalizer(%s) in spec:%s", item, spec)
			return "", nil, false
		}
	}

	return field, normalizers, true
}

// BuildFlowInstanceKeys returns the instance keys that should receive the matched activity.
// If a flow does not declare detection.cache_key for this sigma rule, it falls back to
// the legacy sigma unique_id so existing rules keep their previous grouping behavior.
func (r *Ruleset) BuildFlowInstanceKeys(flowID, sigmaID string, fields map[string]string, dcHostname, uniqueID string) []string {
	if r == nil {
		return fallbackInstanceKeys(uniqueID)
	}

	fr := r.FlowRuleByID[flowID]
	if fr == nil || len(fr.Detection.CacheKey) == 0 {
		return fallbackInstanceKeys(uniqueID)
	}

	specs, ok := fr.Detection.CacheKey[sigmaID]
	if !ok || len(specs) == 0 {
		return fallbackInstanceKeys(uniqueID)
	}

	var parts []string
	for _, spec := range specs {
		field, normalizers, ok := parseCacheKeyFieldSpec(spec)
		if !ok {
			logger.Warnf("invalid cache_key spec(%s) in flow:%s sigma:%s", spec, flowID, sigmaID)
			return nil
		}

		val := fields[field]
		if val == "" && field == "Hostname" {
			val = dcHostname
		}
		val = normalizeFlowCacheKeyValue(field, val, normalizers, dcHostname)
		if val == "" {
			logger.Warnf("empty cache_key field(%s) in flow:%s sigma:%s", field, flowID, sigmaID)
			return nil
		}
		parts = append(parts, val)
	}

	if len(parts) == 0 {
		return nil
	}
	return []string{hashCacheKeyParts(parts)}
}

func fallbackInstanceKeys(uniqueID string) []string {
	uniqueID = strings.TrimSpace(uniqueID)
	if uniqueID == "" {
		return nil
	}
	return []string{uniqueID}
}

func normalizeFlowCacheKeyValue(field, value string, normalizers []string, dcHostname string) string {
	value = strings.TrimSpace(value)
	for _, normalizer := range normalizers {
		switch normalizer {
		case "trim":
			value = strings.TrimSpace(value)
		case "lower":
			value = strings.ToLower(value)
		case "domain":
			value = normalizeDomain(value, dcHostname)
		case "ip":
			value = normalizeIP(value)
		}
	}
	return value
}

func normalizeDomain(domain, dcHostname string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	dcHostname = strings.ToLower(strings.TrimSpace(dcHostname))
	if domain == "" {
		return ""
	}
	if dcHostname == "" || strings.Contains(domain, ".") {
		return domain
	}
	if strings.HasSuffix(dcHostname, domain) {
		return domain
	}

	parts := strings.Split(dcHostname, ".")
	if len(parts) > 1 {
		return strings.Join(parts[1:], ".")
	}
	return domain
}

func normalizeIP(value string) string {
	value = strings.TrimSpace(value)
	ip := net.ParseIP(value)
	if ip == nil {
		return value
	}
	return ip.String()
}

func hashCacheKeyParts(parts []string) string {
	sum := md5.Sum([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}
