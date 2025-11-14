package ldap

import (
	"strings"
	"time"
)

// ParseGeneralizedTime parses LDAP GeneralizedTime format (e.g., "20250508142657.0Z")
// and returns Unix timestamp
func ParseGeneralizedTime(timeStr string) (int64, error) {
	// LDAP GeneralizedTime format: YYYYMMDDHHmmss.0Z or YYYYMMDDHHmmssZ
	// Remove the .0Z or Z suffix and parse
	timeStr = strings.TrimSuffix(timeStr, ".0Z")
	timeStr = strings.TrimSuffix(timeStr, "Z")

	// Parse using the format "20060102150405"
	t, err := time.Parse("20060102150405", timeStr)
	if err != nil {
		return 0, err
	}
	return t.Unix(), nil
}

// ParseGroupType parses AD groupType bitmask and returns scope and category
// Reference: https://learn.microsoft.com/en-us/windows/win32/adschema/a-grouptype
//
// Scope values: BuiltinLocal, Global, DomainLocal, Universal, Unknown
// Category values: Security, Distribution
func ParseGroupType(groupType int64) (scope string, category string) {
	const (
		// Group type flags
		GROUP_TYPE_BUILTIN_LOCAL_GROUP = 0x00000001
		GROUP_TYPE_ACCOUNT_GROUP       = 0x00000002
		GROUP_TYPE_RESOURCE_GROUP      = 0x00000004
		GROUP_TYPE_UNIVERSAL_GROUP     = 0x00000008
		GROUP_TYPE_APP_BASIC_GROUP     = 0x00000010
		GROUP_TYPE_APP_QUERY_GROUP     = 0x00000020
		GROUP_TYPE_SECURITY_ENABLED    = 0x80000000
	)

	// Determine category (Security or Distribution)
	if groupType&GROUP_TYPE_SECURITY_ENABLED != 0 {
		category = "Security"
	} else {
		category = "Distribution"
	}

	// Determine scope
	switch {
	case groupType&GROUP_TYPE_BUILTIN_LOCAL_GROUP != 0:
		scope = "BuiltinLocal"
	case groupType&GROUP_TYPE_ACCOUNT_GROUP != 0:
		scope = "Global"
	case groupType&GROUP_TYPE_RESOURCE_GROUP != 0:
		scope = "DomainLocal"
	case groupType&GROUP_TYPE_UNIVERSAL_GROUP != 0:
		scope = "Universal"
	default:
		scope = "Unknown"
	}

	return scope, category
}
