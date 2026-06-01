package cache

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func constHasher[K comparable](K) uint64 { return 0 }

func TestCacheSetGetDeleteAndOverwrite(t *testing.T) {
	now := int64(100)
	c := New[string, string](
		constHasher[string],
		WithCapacity(512),
		WithExpiration(10*time.Nanosecond),
		OptionFunc(func(o *options) { o.timeUnixNanoFn = func() int64 { return now } }),
	)
	defer c.Stop()

	c.Set("a", "one")
	if got, err := c.Get("a"); err != nil || got != "one" {
		t.Fatalf("Get(a) = %q, %v; want one, nil", got, err)
	}

	c.Set("a", "two")
	if got, err := c.Get("a"); err != nil || got != "two" {
		t.Fatalf("overwritten Get(a) = %q, %v; want two, nil", got, err)
	}

	c.Delete("a")
	if _, err := c.Get("a"); !errors.Is(err, ErrCacheIsNotFound) {
		t.Fatalf("deleted Get(a) err = %v; want ErrCacheIsNotFound", err)
	}
}

func TestCacheExpirationModes(t *testing.T) {
	now := int64(100)
	c := NewStringCache[string](
		WithCapacity(256),
		WithExpiration(10*time.Nanosecond),
		WithDeleteExpiredCacheOnGet(),
		OptionFunc(func(o *options) { o.timeUnixNanoFn = func() int64 { return now } }),
	)
	defer c.Stop()

	c.Set("a", "one")
	now = 110
	if _, err := c.Get("a"); !errors.Is(err, ErrCacheWasExpired) {
		t.Fatalf("expired Get err = %v; want ErrCacheWasExpired", err)
	}
	if _, err := c.Get("a"); !errors.Is(err, ErrCacheIsNotFound) {
		t.Fatalf("expired entry should have been deleted, got err %v", err)
	}
}

func TestCacheUpdateExpirationOnGet(t *testing.T) {
	now := int64(100)
	c := NewStringCache[string](
		WithCapacity(256),
		WithExpiration(10*time.Nanosecond),
		WithUpdateCacheExpirationOnGet(),
		OptionFunc(func(o *options) { o.timeUnixNanoFn = func() int64 { return now } }),
	)
	defer c.Stop()

	c.Set("a", "one")
	now = 105
	if _, err := c.Get("a"); err != nil {
		t.Fatalf("Get before expiration: %v", err)
	}
	now = 114
	if got, err := c.Get("a"); err != nil || got != "one" {
		t.Fatalf("Get after refreshed expiration = %q, %v; want one, nil", got, err)
	}
	now = 125
	if _, err := c.Get("a"); !errors.Is(err, ErrCacheWasExpired) {
		t.Fatalf("Get after refreshed entry expired err = %v; want ErrCacheWasExpired", err)
	}
}

func TestCacheLRUEvictionAndCallback(t *testing.T) {
	var mu sync.Mutex
	evicted := make([]string, 0)
	c := New[string, string](
		constHasher[string],
		WithCapacity(512),
		WithExpiration(time.Second),
		WithEvictCallback(func(k, v any) {
			mu.Lock()
			defer mu.Unlock()
			evicted = append(evicted, k.(string)+"="+v.(string))
		}),
		OptionFunc(func(o *options) { o.timeUnixNanoFn = func() int64 { return 1 } }),
	)
	defer c.Stop()

	c.Set("first", "1")
	c.Set("second", "2")
	if _, err := c.Get("first"); err != nil {
		t.Fatalf("Get(first): %v", err)
	}
	c.Set("third", "3")

	if _, err := c.Get("second"); !errors.Is(err, ErrCacheIsNotFound) {
		t.Fatalf("least recently used entry should be evicted, got %v", err)
	}
	if got, err := c.Get("first"); err != nil || got != "1" {
		t.Fatalf("first should remain after LRU refresh: %q, %v", got, err)
	}
	if got, err := c.Get("third"); err != nil || got != "3" {
		t.Fatalf("third should be present: %q, %v", got, err)
	}

	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(evicted, []string{"second=2"}) {
		t.Fatalf("evicted = %#v; want second=2", evicted)
	}
}

func TestCacheCleanupCycle(t *testing.T) {
	now := int64(100)
	c := New[string, string](
		constHasher[string],
		WithCapacity(256),
		WithExpiration(10*time.Nanosecond),
		OptionFunc(func(o *options) { o.timeUnixNanoFn = func() int64 { return now } }),
	).(*ShardedLRU[string, string])
	defer c.Stop()

	c.Set("a", "one")
	c.Set("b", "two")
	now = 110
	c.cleanupCycle()
	if _, err := c.Get("a"); !errors.Is(err, ErrCacheIsNotFound) {
		t.Fatalf("cleanup should delete expired entry a, got %v", err)
	}
	if _, err := c.Get("b"); !errors.Is(err, ErrCacheIsNotFound) {
		t.Fatalf("cleanup should delete expired entry b, got %v", err)
	}
}

func TestCacheNewPanics(t *testing.T) {
	tests := []struct {
		name string
		fn   func()
	}{
		{"nil hasher", func() { New[string, string](nil) }},
		{"bad capacity", func() { NewStringCache[string](WithCapacity(255)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatalf("expected panic")
				}
			}()
			tt.fn()
		})
	}
}

func TestOptionsDefaultsAndStopIdempotent(t *testing.T) {
	opts := newOptions()
	if opts.capacity != 2048 {
		t.Fatalf("default capacity = %d; want 2048", opts.capacity)
	}
	if opts.expiration != 15*time.Second {
		t.Fatalf("default expiration = %v; want 15s", opts.expiration)
	}

	c := NewStringCache[string](
		WithCapacity(256),
		WithStdGoTimeUnixNano(),
		WithBackgroundCheckInterval(time.Hour),
	)
	c.Stop()
	c.Stop()
}
