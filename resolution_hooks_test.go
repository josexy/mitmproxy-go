package mitmproxy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/v2/metadata"
	"github.com/josexy/xhttp/httptrace"
)

type testIPResolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f testIPResolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type testContextDialerFunc func(context.Context, string, string) (net.Conn, error)

func (f testContextDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

func TestResolutionHooksPreservedByRuntimeProxyChanges(t *testing.T) {
	certPath, keyPath := writeRuntimeTestCA(t, "resolution hooks")
	resolver := testIPResolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	})
	dialer := testContextDialerFunc(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("test") })
	handler, err := NewDynamicMitmProxyHandler(WithCACertPath(certPath), WithCAKeyPath(keyPath), WithIPResolver(resolver), WithContextDialer(dialer))
	if err != nil {
		t.Fatal(err)
	}
	defer handler.Cleanup()
	for _, change := range []func() error{
		func() error { return handler.SetProxy("http://127.0.0.1:8888") },
		func() error { return handler.SetDialer(&net.Dialer{Timeout: time.Second}) },
		func() error { return handler.SetProxyDisabled(true) },
	} {
		if err := change(); err != nil {
			t.Fatal(err)
		}
		cfg := handler.(*mitmProxyHandler).config.Load()
		if cfg.proxyDialer.ipResolver == nil || cfg.proxyDialer.contextDialer == nil {
			t.Fatal("runtime rebuild dropped resolution hooks")
		}
		addr, err := cfg.proxyDialer.resolveTCPAddr(context.Background(), "tcp", "hook.test:443", nil)
		if err != nil || addr.IP.String() != "127.0.0.1" {
			t.Fatalf("resolver hook: %v %v", addr, err)
		}
	}
}

func TestContextDialerRetainsRealConnectionTiming(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
	}()
	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: time.Second})
	dialer.contextDialer = testContextDialerFunc(func(ctx context.Context, network, _ string) (net.Conn, error) {
		trace := httptrace.ContextClientTrace(ctx)
		trace.DNSStart(httptrace.DNSStartInfo{Host: "hook.test"})
		trace.DNSDone(httptrace.DNSDoneInfo{Addrs: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}})
		return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
	})
	// Supply a caller DNSStart hook; the dialer recorder itself records the
	// boundary before invoking the custom dialer.
	ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{DNSStart: func(httptrace.DNSStartInfo) {}})
	md := metadata.NewMD()
	conn, err := dialer.DialTCPContextWithMetadata(ctx, "hook.test:443", md)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	got := md.MD()
	if got.DNSLookupStartTs.IsZero() || got.DNSLookupCompletedTs.Before(got.DNSLookupStartTs) || got.SocketConnectStartTs.Before(got.DNSLookupCompletedTs) || got.SocketConnectCompletedTs.Before(got.SocketConnectStartTs) {
		t.Fatalf("missing or reordered timing: %+v", got)
	}
}

func TestContextDialerTimeoutAndNoFabricatedCompletion(t *testing.T) {
	dialer := NewProxyDialer(nil, &net.Dialer{Timeout: 20 * time.Millisecond})
	dialer.contextDialer = testContextDialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() })
	md := metadata.NewMD()
	if _, err := dialer.DialTCPContextWithMetadata(context.Background(), "hook.test:443", md); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	got := md.MD()
	if !got.DNSLookupCompletedTs.IsZero() || !got.SocketConnectCompletedTs.IsZero() {
		t.Fatalf("failure fabricated completion: %+v", got)
	}
}

func TestContextDialerRespectsConfiguredCancelChannel(t *testing.T) {
	cancel := make(chan struct{})
	started := make(chan struct{})
	dialer := NewProxyDialer(nil, &net.Dialer{Cancel: cancel})
	dialer.contextDialer = testContextDialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	finished := make(chan error, 1)
	go func() {
		_, err := dialer.DialTCPContextWithMetadata(context.Background(), "hook.test:443", metadata.NewMD())
		finished <- err
	}()
	<-started
	close(cancel)
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("configured cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("configured cancellation did not reach the custom dialer")
	}
}
