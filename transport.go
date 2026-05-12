package mitmproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"golang.org/x/net/http2"
)

type unifiedTransport struct {
	defaultTransport http.RoundTripper
	h2Transport      http.RoundTripper
	h2cTransport     http.RoundTripper
}

func (t *unifiedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.ProtoMajor == 2 {
		return t.h2Transport.RoundTrip(req)
	}
	return t.defaultTransport.RoundTrip(req)
}

func newTransport(
	dialFn func(ctx context.Context, network, addr string) (net.Conn, error),
	idleConnTimeout time.Duration,
) http.RoundTripper {
	// configure transport
	return &unifiedTransport{
		defaultTransport: &http.Transport{
			DialContext:        dialFn,
			DialTLSContext:     dialFn,
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
			IdleConnTimeout:    idleConnTimeout,
		},
		h2Transport: &http2.Transport{
			AllowHTTP:          true,
			DisableCompression: true,
			IdleConnTimeout:    idleConnTimeout,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialFn(ctx, network, addr)
			},
		},
	}
}
