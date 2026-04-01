package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"math/rand"
	"time"

	"github.com/josexy/mitmproxy-go/internal/cache"
	"github.com/josexy/mitmproxy-go/internal/cert"
)

var errNoPriKey = errors.New("no available private key")

type priKeyPool struct {
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
	var n, m = len(p.keys), cap(p.keys)
	if m == 0 {
		return nil, errNoPriKey
	}
	if n < m {
		key, err := cert.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		p.keys = append(p.keys, key)
		return key, nil
	}
	index := p.rand.Intn(n)
	key := p.keys[index]
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
