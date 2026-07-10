package mitmproxy

import (
	"sync"
	"testing"
)

func TestPrivateKeyPoolGeneratesOneReusableKey(t *testing.T) {
	pool := newPriKeyPool()
	const callers = 16
	keys := make(chan any, callers)
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			key, err := pool.Get()
			if err != nil {
				t.Errorf("Get: %v", err)
				return
			}
			keys <- key
		})
	}
	wg.Wait()
	close(keys)
	var first any
	for key := range keys {
		if first == nil {
			first = key
			continue
		}
		if key != first {
			t.Fatal("private key pool generated more than one key")
		}
	}
}

func TestCertificateCacheKeyUsesNormalizedSNI(t *testing.T) {
	if got := certificateCacheKey("API.Example.COM.", "192.0.2.1"); got != "api.example.com" {
		t.Fatalf("cache key = %q; want api.example.com", got)
	}
	if got := certificateCacheKey("", "Example.COM."); got != "example.com" {
		t.Fatalf("fallback cache key = %q; want example.com", got)
	}
}
