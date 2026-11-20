package clock

import (
	"sync"
	"time"
)

type Clock interface{ Now() time.Time }

type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Manual is a concurrency-safe test clock.
type Manual struct {
	mu  sync.RWMutex
	now time.Time
}

func NewManual(t time.Time) *Manual { return &Manual{now: t} }
func (c *Manual) Now() time.Time {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.now
}
func (c *Manual) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}
