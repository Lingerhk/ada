package service

import (
	"sync"
	"time"
)

// activeTmThrottle is the minimum interval between two ActiveTm writes for the
// same user or access key.
const activeTmThrottle = 5 * time.Minute

// activeTmTracker remembers when the ActiveTm of a user / access key was last
// persisted so that authentication does not hit MongoDB on every request.
// Methods are safe on a nil receiver (always update, remember nothing), which
// keeps ad-hoc GrpcService values usable in tests.
type activeTmTracker struct {
	mu       sync.RWMutex
	lastSeen map[string]time.Time
	throttle time.Duration
}

func newActiveTmTracker(throttle time.Duration) *activeTmTracker {
	return &activeTmTracker{lastSeen: make(map[string]time.Time), throttle: throttle}
}

// shouldUpdate reports whether key has not been persisted within the throttle
// window.
func (t *activeTmTracker) shouldUpdate(key string) bool {
	if t == nil {
		return true
	}
	t.mu.RLock()
	last, ok := t.lastSeen[key]
	t.mu.RUnlock()
	return !ok || time.Since(last) >= t.throttle
}

// mark records that key was persisted at now.
func (t *activeTmTracker) mark(key string, now time.Time) {
	if t == nil {
		return
	}
	t.mu.Lock()
	t.lastSeen[key] = now
	t.mu.Unlock()
}
