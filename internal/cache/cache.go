package cache

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

const (
	shardCount         = 256
	shardMask          = shardCount - 1
	cleanupSampleCount = 20
)

var (
	ErrCacheIsNotFound = errors.New("cache is not found")
	ErrCacheWasExpired = errors.New("cache was expired")
)

type Hasher[K comparable] func(K) uint64

type EvictCallback func(any, any)

type Cache[K comparable, V any] interface {
	Get(K) (V, error)
	Set(K, V)
	Delete(K)
	Stop()
}

type entry[K comparable, V any] struct {
	key        K
	value      V
	expiresAt  int64 // nanoseconds
	prev, next *entry[K, V]
}

type cacheShard[K comparable, V any] struct {
	sync.Mutex
	items      map[K]*entry[K, V]
	head, tail *entry[K, V]
	capacity   int
	evictFn    EvictCallback
}

type ShardedLRU[K comparable, V any] struct {
	*options
	nowUnixNano int64
	hasher      Hasher[K]
	onceClose   sync.Once
	closeCh     chan struct{}
	shards      []*cacheShard[K, V]
}

func New[K comparable, V any](hashFunc Hasher[K], opt ...Option) Cache[K, V] {
	opts := newOptions(opt...)

	if hashFunc == nil {
		panic("hashFunc is required for sharded cache")
	}
	if opts.capacity&shardMask != 0 {
		panic(fmt.Errorf("capacity must be a multiple of %d", shardCount))
	}

	shardCap := opts.capacity / shardCount

	c := &ShardedLRU[K, V]{
		options:     opts,
		hasher:      hashFunc,
		nowUnixNano: time.Now().UnixNano(),
		closeCh:     make(chan struct{}, 1),
		shards:      make([]*cacheShard[K, V], shardCount),
	}

	for i := range shardCount {
		c.shards[i] = newShard[K, V](shardCap, opts.evictFn)
	}

	if opts.bgCheckInterval > 0 {
		go c.bgCleanup()
	}
	// use fast time instead of go time.Now()
	if opts.timeUnixNanoFn == nil {
		opts.timeUnixNanoFn = func() int64 { return atomic.LoadInt64(&c.nowUnixNano) }
		go c.updateTimeTicker()
	}

	return c
}

func newShard[K comparable, V any](cap int, evictFn EvictCallback) *cacheShard[K, V] {
	s := &cacheShard[K, V]{
		items:    make(map[K]*entry[K, V], cap),
		capacity: cap,
		head:     &entry[K, V]{}, // Sentinel Head
		tail:     &entry[K, V]{}, // Sentinel Tail
		evictFn:  evictFn,
	}
	s.head.next = s.tail
	s.tail.prev = s.head
	return s
}

func (c *ShardedLRU[K, V]) Get(key K) (V, error) {
	hash := c.hasher(key)
	shard := c.shards[hash&shardMask]

	shard.Lock()
	defer shard.Unlock()

	entry, exists := shard.items[key]
	if !exists {
		var zero V
		return zero, ErrCacheIsNotFound
	}

	timeNow := c.timeUnixNanoFn()
	if entry.expiresAt > 0 && timeNow >= entry.expiresAt {
		// delete expired cache when get
		if c.deleteExpiredCacheOnGet {
			shard.removeNode(entry)
		}
		var zero V
		return zero, ErrCacheWasExpired
	}

	// update cache expiration when get
	if c.updateCacheExpirationOnGet {
		entry.expiresAt = timeNow + c.expiration.Nanoseconds()
	}

	shard.moveToHead(entry)

	return entry.value, nil
}

func (c *ShardedLRU[K, V]) Set(key K, value V) {
	hash := c.hasher(key)
	shard := c.shards[hash&shardMask]

	shard.Lock()
	defer shard.Unlock()

	node, exists := shard.items[key]
	if exists {
		node.value = value
		node.expiresAt = c.timeUnixNanoFn() + c.expiration.Nanoseconds()
		shard.moveToHead(node)
		return
	}

	newEntry := &entry[K, V]{
		key:       key,
		value:     value,
		expiresAt: c.timeUnixNanoFn() + c.expiration.Nanoseconds(),
	}

	if len(shard.items) >= shard.capacity {
		shard.removeOldest()
	}

	shard.items[key] = newEntry
	shard.addToHead(newEntry)
}

func (c *ShardedLRU[K, V]) Delete(key K) {
	hash := c.hasher(key)
	shard := c.shards[hash&shardMask]

	shard.Lock()
	defer shard.Unlock()

	if entry, exists := shard.items[key]; exists {
		shard.removeNode(entry)
	}
}

func (c *ShardedLRU[K, V]) updateTimeTicker() {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			atomic.StoreInt64(&c.nowUnixNano, time.Now().UnixNano())
		}
	}
}

func (c *ShardedLRU[K, V]) bgCleanup() {
	interval := c.bgCheckInterval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-c.closeCh:
			return
		case <-timer.C:
			c.cleanupCycle()
			timer.Reset(interval)
		}
	}
}

func (c *ShardedLRU[K, V]) cleanupCycle() {
	timeNow := c.timeUnixNanoFn()

	for _, shard := range c.shards {
		shard.Lock()
		cleanCount := 0
		for _, entry := range shard.items {
			if cleanCount >= cleanupSampleCount {
				break
			}
			if entry.expiresAt > 0 && timeNow >= entry.expiresAt {
				shard.removeNode(entry)
			}
			cleanCount++
		}
		shard.Unlock()

	}
}

func (c *ShardedLRU[K, V]) Stop() {
	c.onceClose.Do(func() {
		close(c.closeCh)
	})
}

func (s *cacheShard[K, V]) addToHead(n *entry[K, V]) {
	n.prev = s.head
	n.next = s.head.next
	s.head.next.prev = n
	s.head.next = n
}

func (s *cacheShard[K, V]) removeNode(n *entry[K, V]) {
	n.prev.next = n.next
	n.next.prev = n.prev
	n.prev = nil // avoid memory leak
	n.next = nil // avoid memory leak

	delete(s.items, n.key)

	if s.evictFn != nil {
		s.evictFn(n.key, n.value)
	}
}

func (s *cacheShard[K, V]) moveToHead(n *entry[K, V]) {
	n.prev.next = n.next
	n.next.prev = n.prev

	s.addToHead(n)
}

func (s *cacheShard[K, V]) removeOldest() {
	oldest := s.tail.prev
	if oldest != s.head {
		s.removeNode(oldest)
	}
}

// StringHasher computes an FNV-1 hash of s. It is implemented inline (rather
// than via hash/fnv) so it allocates nothing and avoids unsafe; the result is
// only used to select a shard, so the exact value need not be stable across
// builds, but it stays bit-for-bit compatible with fnv.New64.
func StringHasher(s string) uint64 {
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(s); i++ {
		h *= prime64
		h ^= uint64(s[i])
	}
	return h
}

func NewStringCache[V any](opt ...Option) Cache[string, V] {
	return New[string, V](StringHasher, opt...)
}
