package common

import "strings"

// MaskSensitive keeps enough context for debugging without leaking the full value.
func MaskSensitive(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	runes := []rune(value)
	switch len(runes) {
	case 1:
		return "*"
	case 2:
		return string(runes[:1]) + "*"
	case 3, 4:
		return string(runes[:1]) + strings.Repeat("*", len(runes)-2) + string(runes[len(runes)-1:])
	default:
		return string(runes[:2]) + strings.Repeat("*", len(runes)-4) + string(runes[len(runes)-2:])
	}
}
