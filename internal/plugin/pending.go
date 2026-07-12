package plugin

import (
	"sync"
	"time"
)

type pendingDecision struct {
	category string
	created  time.Time
}

// pendingCache carries only the coarse category across CPA's model.route ->
// executor callback split. It is bounded and time-limited, and never retains
// request text, headers, credentials, or other prompt-derived material.
type pendingCache struct {
	mu    sync.Mutex
	items map[string]pendingDecision
	limit int
	ttl   time.Duration
	now   func() time.Time
}

func newPendingCache(limit int, ttl time.Duration) pendingCache {
	return pendingCache{
		items: make(map[string]pendingDecision),
		limit: limit,
		ttl:   ttl,
		now:   time.Now,
	}
}

func (cache *pendingCache) put(hash, category string) {
	if cache == nil || hash == "" {
		return
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	now := cache.now()
	cache.pruneExpiredLocked(now)
	if cache.limit <= 0 {
		return
	}
	if len(cache.items) >= cache.limit {
		var oldestKey string
		var oldest time.Time
		for key, item := range cache.items {
			if oldestKey == "" || item.created.Before(oldest) {
				oldestKey = key
				oldest = item.created
			}
		}
		delete(cache.items, oldestKey)
	}
	cache.items[hash] = pendingDecision{category: category, created: now}
}

func (cache *pendingCache) get(hash string) (pendingDecision, bool) {
	if cache == nil || hash == "" {
		return pendingDecision{}, false
	}
	cache.mu.Lock()
	defer cache.mu.Unlock()
	item, ok := cache.items[hash]
	if !ok {
		return pendingDecision{}, false
	}
	if cache.ttl > 0 && cache.now().Sub(item.created) > cache.ttl {
		delete(cache.items, hash)
		return pendingDecision{}, false
	}
	return item, true
}

func (cache *pendingCache) clear() {
	if cache == nil {
		return
	}
	cache.mu.Lock()
	clear(cache.items)
	cache.mu.Unlock()
}

func (cache *pendingCache) pruneExpiredLocked(now time.Time) {
	if cache.ttl <= 0 {
		return
	}
	for key, item := range cache.items {
		if now.Sub(item.created) > cache.ttl {
			delete(cache.items, key)
		}
	}
}
