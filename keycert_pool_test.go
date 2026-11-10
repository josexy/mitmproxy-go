package mitmproxy

import (
	"crypto/tls"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestCertFlightSharesConcurrentGeneration(t *testing.T) {
	var flight certFlight
	var generations atomic.Int32
	release := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if _, err := flight.do("example.test", func() (tls.Certificate, error) {
				generations.Add(1)
				<-release
				return tls.Certificate{}, nil
			}); err != nil {
				t.Errorf("do: %v", err)
			}
		})
	}
	waitForCondition(t, time.Second, func() bool { return generations.Load() == 1 })
	// Give the remaining callers time to join the flight in progress.
	time.Sleep(100 * time.Millisecond)
	close(release)
	wg.Wait()
	if got := generations.Load(); got != 1 {
		t.Fatalf("generations = %d; want 1", got)
	}
	if _, err := flight.do("example.test", func() (tls.Certificate, error) {
		generations.Add(1)
		return tls.Certificate{}, nil
	}); err != nil || generations.Load() != 2 {
		t.Fatalf("finished flight was reused: generations=%d err=%v", generations.Load(), err)
	}
}
