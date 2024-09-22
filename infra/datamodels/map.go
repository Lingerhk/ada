package datamodels

import (
	"strings"
	"time"
)

const ArgTimeFormat = "2006-01-02 15:04:05"

// Map is a nested map with helper methods for recursive lookups
type Map map[string]any

// Select implements selection interface for sigma rule engine
func (d Map) Select(key string) (any, bool) {
	return d.Get(strings.Split(key, ".")...)
}

// Keywords implements keyword interface for sigma rule engine. For now it's a stub.
func (d Map) Keywords() ([]string, bool) {
	return nil, false
}

func (d Map) Set(value any, key ...string) error {
	if len(key) == 0 {
		return nil
	}
	if len(key) == 1 {
		d[key[0]] = value
	} else {
		val, ok := d[key[0]]
		if ok {
			switch res := val.(type) {
			case map[string]any:
				// recurse into existing map
				return Map(res).Set(value, key[1:]...)
			case Map:
				// recurse into existing map
				return res.Set(value, key[1:]...)
			default:
				e := Map{}
				d[key[0]] = e
				return e.Set(value, key[1:]...)
			}
		}
		e := Map{}
		d[key[0]] = e
		return e.Set(value, key[1:]...)
	}
	return nil
}

// Get is a helper for doing recursive lookups into nested maps (nested JSON). Key argument is a
// slice of strings
func (d Map) Get(key ...string) (any, bool) {
	if len(key) == 0 {
		return nil, false
	}
	if val, ok := d[key[0]]; ok {
		switch res := val.(type) {
		case Map:
			// key has only one item, user wants the map itselt, not subelement
			if len(key) == 1 {
				return res, ok
			}
			// recurse with key remainder
			return res.Get(key[1:]...)
		case map[string]any:
			// key has only one item, user wants the map itselt, not subelement
			if len(key) == 1 {
				return res, ok
			}
			// recurse with key remainder
			return Map(res).Get(key[1:]...)
		default:
			return val, ok
		}
	}
	return nil, false
}

// GetString wraps Get to cast item to string.
func (d Map) GetString(key ...string) (string, bool) {
	val, ok := d.Get(key...)
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	if !ok {
		return "", false
	}
	return str, true
}

func (d Map) GetTimestamp(key ...string) (time.Time, bool, error) {
	val, ok := d.GetString(key...)
	if !ok {
		return time.Time{}, false, nil
	}
	ts, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return time.Time{}, false, err
	}
	return ts, true, nil
}

// GetNumber retrieves JSON numeric value which are by spec floating points
func (d Map) GetNumber(key ...string) (float64, bool) {
	val, ok := d.Get(key...)
	if !ok {
		return -1, false
	}
	n, ok := val.(float64)
	if !ok {
		return -1, false
	}
	return n, true
}
