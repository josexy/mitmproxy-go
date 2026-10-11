package mitmproxy

import (
	"context"
	"errors"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/v2/metadata"
	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
	"github.com/josexy/xhttp/httptrace"
)

func connectionTestClock(count int) *sequenceTimingClock {
	base := time.UnixMicro(1_000_000)
	timestamps := make([]time.Time, count)
	for i := range timestamps {
		timestamps[i] = base.Add(time.Duration(i) * 125 * time.Microsecond)
	}
	return &sequenceTimingClock{timestamps: timestamps}
}

func TestLegacyDialerUsesConnectionTimingClock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	clock := connectionTestClock(3)
	ctx := withTimingClock(context.Background(), clock)
	md := metadata.NewMD()
	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
	conn, err := dialer.DialTCPContextWithMetadata(ctx, net.JoinHostPort("localhost", u.Port()), md)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := md.MD()
	if !got.DNSLookupStartTs.Equal(clock.timestamps[0]) ||
		!got.DNSLookupCompletedTs.Equal(clock.timestamps[1]) ||
		!got.SocketConnectStartTs.Equal(clock.timestamps[1]) ||
		!got.SocketConnectCompletedTs.Equal(clock.timestamps[2]) {
		t.Fatalf("legacy dialer did not preserve precise boundaries: %+v", got)
	}
}

func TestCustomDialerAndRemoteMetadataShareConnectionTimingClock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
	dialer.contextDialer = testContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		trace := httptrace.ContextClientTrace(ctx)
		trace.DNSDone(httptrace.DNSDoneInfo{Addrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}})
		return (&net.Dialer{}).DialContext(ctx, network, u.Host)
	})
	clock := connectionTestClock(5)
	baseMD, streamMD := metadata.NewMD(), metadata.NewMD()
	connCtx := &biConnContext{config: &runtimeConfig{proxyDialer: dialer}, baseMetadata: baseMD}
	ctx := metadata.AppendToContext(withTimingClock(context.Background(), clock), streamMD)
	conn, err := connCtx.dialTCPWithMetadata(ctx, "cached.test:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, md := range []metadata.MD{baseMD.MD(), streamMD.MD()} {
		if !md.DNSLookupStartTs.Equal(clock.timestamps[0]) ||
			!md.DNSLookupCompletedTs.Equal(clock.timestamps[1]) ||
			!md.SocketConnectStartTs.Equal(clock.timestamps[2]) ||
			!md.SocketConnectCompletedTs.Equal(clock.timestamps[3]) ||
			!md.RemoteConnectionEstablishedTs.Equal(clock.timestamps[4]) {
			t.Fatalf("connection phases used different clocks: %+v", md)
		}
	}
}

func TestProxyDestinationAndEndpointShareConnectionTimingClock(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Host != "127.0.0.1:443" {
			t.Errorf("unexpected tunnel request: %s %s", r.Method, r.Host)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	dialer := NewProxyDialer(proxyURL, &net.Dialer{Timeout: time.Second})
	dialer.ipResolver = testIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	clock := connectionTestClock(4)
	md := metadata.NewMD()
	conn, err := dialer.DialTCPContextWithMetadata(withTimingClock(context.Background(), clock), "cached.test:443", md)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got := md.MD()
	if !got.DNSLookupStartTs.Equal(clock.timestamps[0]) ||
		!got.DNSLookupCompletedTs.Equal(clock.timestamps[1]) ||
		!got.SocketConnectStartTs.Equal(clock.timestamps[2]) ||
		!got.SocketConnectCompletedTs.Equal(clock.timestamps[3]) {
		t.Fatalf("proxy phases used different clocks: %+v", got)
	}
}

func TestPreciseDNSFailureDoesNotCreateSocketTimings(t *testing.T) {
	for _, lookupErr := range []error{errors.New("lookup failed"), context.Canceled} {
		t.Run(lookupErr.Error(), func(t *testing.T) {
			proxyURL, _ := url.Parse("http://127.0.0.1:1")
			dialer := NewProxyDialer(proxyURL, nil)
			dialer.ipResolver = testIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
				return nil, lookupErr
			})
			clock := connectionTestClock(2)
			md := metadata.NewMD()
			_, err := dialer.DialTCPContextWithMetadata(withTimingClock(context.Background(), clock), "failed.test:443", md)
			if !errors.Is(err, lookupErr) {
				t.Fatalf("lookup error = %v, want %v", err, lookupErr)
			}
			got := md.MD()
			if !got.DNSLookupStartTs.Equal(clock.timestamps[0]) || !got.DNSLookupCompletedTs.Equal(clock.timestamps[1]) ||
				!got.SocketConnectStartTs.IsZero() || !got.SocketConnectCompletedTs.IsZero() {
				t.Fatalf("failed lookup changed phase semantics: %+v", got)
			}
		})
	}
}

func TestDNSCacheHitKeepsTCPBoundaries(t *testing.T) {
	for _, path := range []string{"direct", "proxy destination", "proxy endpoint only"} {
		t.Run(path, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			serverURL, _ := url.Parse(server.URL)
			dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
			if path != "direct" {
				dialer.proxyURL = serverURL
				dialer.ipResolver = testIPResolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) {
					if path == "proxy destination" {
						ReportDNSCacheHit(ctx)
					}
					return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
				})
			}
			dialer.contextDialer = testContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Report a hit even for the proxy endpoint: it must not replace
				// the separate destination lookup's timing.
				ReportDNSCacheHit(ctx)
				trace := httptrace.ContextClientTrace(ctx)
				trace.DNSDone(httptrace.DNSDoneInfo{Addrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}})
				return (&net.Dialer{}).DialContext(ctx, network, serverURL.Host)
			})
			clock := connectionTestClock(4)
			md := metadata.NewMD()
			conn, err := dialer.DialTCPContextWithMetadata(withTimingClock(context.Background(), clock), "cached.test:443", md)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			dnsEnd := clock.timestamps[0]
			if path == "proxy endpoint only" {
				dnsEnd = clock.timestamps[1]
			}
			got := md.MD()
			if !got.DNSLookupStartTs.Equal(clock.timestamps[0]) || !got.DNSLookupCompletedTs.Equal(dnsEnd) ||
				!got.SocketConnectStartTs.Equal(clock.timestamps[2]) || !got.SocketConnectCompletedTs.Equal(clock.timestamps[3]) {
				t.Fatalf("cache hit changed connection boundaries: %+v", got)
			}
		})
	}
}

func TestDNSCacheHitSignalIsScopedToDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
	hit := true
	dialer.contextDialer = testContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		if hit {
			ReportDNSCacheHit(ctx)
		}
		httptrace.ContextClientTrace(ctx).DNSDone(httptrace.DNSDoneInfo{Addrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}})
		return (&net.Dialer{}).DialContext(ctx, network, u.Host)
	})
	clock := connectionTestClock(8)
	ctx := withTimingClock(context.Background(), clock)
	// A report outside the dial is harmless and cannot mark a future lookup.
	ReportDNSCacheHit(ctx)
	for i := range 2 {
		md := metadata.NewMD()
		conn, err := dialer.DialTCPContextWithMetadata(ctx, "cached.test:443", md)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
		got := md.MD()
		duration := got.DNSLookupCompletedTs.Sub(got.DNSLookupStartTs)
		if (i == 0 && duration != 0) || (i == 1 && duration != 125*time.Microsecond) {
			t.Fatalf("dial %d DNS duration = %v", i, duration)
		}
		hit = false
	}
}
