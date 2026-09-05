package mitmproxy

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"sync"
	"time"

	"github.com/josexy/mitmproxy-go/v2/internal/cache"
	"github.com/josexy/mitmproxy-go/v2/internal/cert"
)

var errNoPriKey = errors.New("no available private key")

type priKeyPool struct {
	once sync.Once
	key  *rsa.PrivateKey
	err  error
}

func newPriKeyPool() *priKeyPool {
	return &priKeyPool{}
}

func (p *priKeyPool) Get() (*rsa.PrivateKey, error) {
	p.once.Do(func() {
		p.key, p.err = cert.GeneratePrivateKey()
	})
	if p.err != nil {
		return nil, p.err
	}
	if p.key == nil {
		return nil, errNoPriKey
	}
	return p.key, nil
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
