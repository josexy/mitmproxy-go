package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/josexy/mitmproxy-go/internal/cache"
	"github.com/josexy/mitmproxy-go/internal/cert"
)

var errNoPriKey = errors.New("no available private key")

type priKeyPool struct {
	mu   sync.Mutex
	rand *rand.Rand
	keys []*rsa.PrivateKey
}

func newPriKeyPool(maxSize int) *priKeyPool {
	if maxSize <= 0 {
		maxSize = 10
	}
	pool := &priKeyPool{
		rand: rand.New(rand.NewSource(time.Now().UnixNano())),
		keys: make([]*rsa.PrivateKey, 0, maxSize),
	}
	return pool
}

func (p *priKeyPool) Get() (*rsa.PrivateKey, error) {
	p.mu.Lock()
	n, m := len(p.keys), cap(p.keys)
	if m == 0 {
		p.mu.Unlock()
		return nil, errNoPriKey
	}
	if n >= m {
		// pool is full: reuse an existing key. math/rand is not safe for
		// concurrent use, so the pick must stay under the lock.
		key := p.keys[p.rand.Intn(n)]
		p.mu.Unlock()
		return key, nil
	}
	p.mu.Unlock()

	// Generate the key without holding the lock: RSA key generation is
	// expensive and would otherwise serialize every concurrent cert mint.
	key, err := cert.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	// Another goroutine may have filled the pool meanwhile; only append while
	// there is still room so the pool stays bounded by its capacity.
	if len(p.keys) < cap(p.keys) {
		p.keys = append(p.keys, key)
	}
	p.mu.Unlock()
	return key, nil
}

type certPool struct {
	cache.Cache[string, tls.Certificate]
}

func newServerCertPool(capacity int, bgCheckInterval, certExpired time.Duration) *certPool {
	if capacity <= 0 {
		capacity = 2048
	}
	if bgCheckInterval <= 0 {
		bgCheckInterval = time.Second * 30
	}
	if certExpired <= 0 {
		certExpired = time.Second * 15
	}
	return &certPool{
		Cache: cache.NewStringCache[tls.Certificate](
			cache.WithCapacity(capacity),
			cache.WithStdGoTimeUnixNano(),
			cache.WithBackgroundCheckInterval(bgCheckInterval),
			cache.WithExpiration(certExpired),
			cache.WithUpdateCacheExpirationOnGet(),
			// cache.WithDeleteExpiredCacheOnGet(),
		),
	}
}
