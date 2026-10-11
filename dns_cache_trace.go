package mitmproxy

import (
	"context"
	"sync/atomic"
)

type dnsCacheHitContextKey struct{}

func withDNSCacheHit(ctx context.Context) (context.Context, *atomic.Bool) {
	hit := new(atomic.Bool)
	return context.WithValue(ctx, dnsCacheHitContextKey{}, hit), hit
}

// ReportDNSCacheHit marks a successful application-cache lookup in an
// IPResolver or ContextDialer. Call it before the dialer's DNSDone hook.
// Connection metadata then reports a zero-length DNS phase while preserving
// actual TCP/TLS timestamps. In-flight shared lookups are not cache hits.
// Calls outside a recorded DNS phase have no effect.
func ReportDNSCacheHit(ctx context.Context) {
	if hit, ok := ctx.Value(dnsCacheHitContextKey{}).(*atomic.Bool); ok {
		hit.Store(true)
	}
}
