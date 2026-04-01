package mitmproxy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

type UnifiedTransport struct {
	defaultTransport http.RoundTripper
	h2Transport      http.RoundTripper
	h2cTransport     http.RoundTripper
}

func (t *UnifiedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.ProtoMajor == 2 {
		return t.h2Transport.RoundTrip(req)
	}
	return t.defaultTransport.RoundTrip(req)
}

func NewTransport(dialFn func(ctx context.Context, network, addr string) (net.Conn, error)) *UnifiedTransport {
	// configure transport
	return &UnifiedTransport{
		defaultTransport: &http.Transport{
			DialContext:        dialFn,
			DialTLSContext:     dialFn,
			ForceAttemptHTTP2:  true,
			DisableCompression: true,
		},
		h2Transport: &http2.Transport{
			AllowHTTP:          true,
			DisableCompression: true,
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialFn(ctx, network, addr)
			},
		},
	}
}
