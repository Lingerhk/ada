package datamodels

import (
	"sync"
	"time"
)

type SafeMap struct {
	sync.RWMutex
	data Map
}

func (d *SafeMap) Set(value any, key ...string) error {
	d.Lock()
	defer d.Unlock()
	return d.data.Set(value, key...)
}

// Get is a helper for doing recursive lookups into nested maps (nested JSON). Key argument is a
// slice of strings
func (d *SafeMap) Get(key ...string) (any, bool) {
	d.RLock()
	defer d.RUnlock()
	return d.data.Get(key...)
}

// GetString wraps Get to cast item to string.
func (d *SafeMap) GetString(key ...string) (string, bool) {
	d.RLock()
	defer d.RUnlock()
	return d.data.GetString(key...)
}

func (d *SafeMap) GetTimestamp(key ...string) (time.Time, bool, error) {
	d.RLock()
	defer d.RUnlock()
	return d.data.GetTimestamp(key...)
}

// GetNumber retrieves JSON numeric value which are by spec floating points
func (d *SafeMap) GetNumber(key ...string) (float64, bool) {
	d.RLock()
	defer d.RUnlock()
	return d.data.GetNumber(key...)
}

func (d *SafeMap) Raw() Map { return d.data }

func NewSafeMap(data Map) *SafeMap {
	sm := &SafeMap{
		RWMutex: sync.RWMutex{},
	}
	if data != nil {
		sm.data = data
	} else {
		sm.data = make(Map)
	}

	return sm
}
