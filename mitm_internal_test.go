package mitmproxy

import (
	"context"
	"crypto/x509/pkix"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/internal/cert"
	"github.com/josexy/mitmproxy-go/metadata"
)

func TestDialTCPWithMetadataRefreshesCurrentAndBaseRemoteMetadata(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptedCh := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			acceptedCh <- conn
		}
	}()

	baseMD := metadata.NewMD()
	streamMD := metadata.NewMD()
	connCtx := &biConnContext{
		config: &runtimeConfig{
			proxyDialer: NewProxyDialer(nil, &net.Dialer{Timeout: time.Second}),
		},
		baseMetadata: baseMD,
	}

	ctx := metadata.AppendToContext(context.Background(), streamMD)
	conn, err := connCtx.dialTCPWithMetadata(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	select {
	case accepted := <-acceptedCh:
		defer accepted.Close()
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for accepted connection")
	}

	wantAddr := metadata.ConnectionAddrInfo{
		SourceAddr:      getLocalAddrPortFromConn(conn),
		DestinationAddr: getRemoteAddrPortFromConn(conn),
	}
	assertRemoteMetadataRefreshed(t, "stream", streamMD.MD(), wantAddr)
	assertRemoteMetadataRefreshed(t, "base", baseMD.MD(), wantAddr)
}

func assertRemoteMetadataRefreshed(t *testing.T, name string, md metadata.MD, wantAddr metadata.ConnectionAddrInfo) {
	t.Helper()
	if md.RemoteConnectionEstablishedTs.IsZero() {
		t.Fatalf("%s remote connection established timestamp was not set", name)
	}
	if md.SocketConnectStartTs.IsZero() || md.SocketConnectCompletedTs.IsZero() {
		t.Fatalf("%s socket timing was not set: %#v", name, md)
	}
	if md.RemoteAddrInfo != wantAddr {
		t.Fatalf("%s remote addr = %#v, want %#v", name, md.RemoteAddrInfo, wantAddr)
	}
}

func TestCleanupClosesActiveClientConnections(t *testing.T) {
	caCertPath, caKeyPath := writeTestCA(t)
	upstreamStarted := make(chan struct{})
	upstreamRelease := make(chan struct{})
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if upstreamRequests.Add(1) == 1 {
			close(upstreamStarted)
		}
		<-upstreamRelease
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	defer close(upstreamRelease)

	handler, err := NewMitmProxyHandler(
		WithCACertPath(caCertPath),
		WithCAKeyPath(caKeyPath),
	)
	if err != nil {
		t.Fatal(err)
	}

	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodGet, upstream.URL, nil)
	if err != nil {
		t.Fatal(err)
	}

	clientConn, proxyConn := net.Pipe()
	defer clientConn.Close()

	serveDone := make(chan error, 1)
	go func() {
		serveDone <- handler.Serve(AppendToRequestContext(context.Background(), ReqContext{
			Hostport: targetURL.Host,
			Request:  req,
		}), proxyConn)
	}()

	select {
	case <-upstreamStarted:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for upstream request")
	}

	handler.Cleanup()

	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err == nil {
		if _, err := clientConn.Read(make([]byte, 1)); err == nil {
			t.Fatal("client connection remained open after Cleanup")
		}
	}

	select {
	case <-serveDone:
	case <-time.After(time.Second):
		t.Fatal("Serve did not exit after Cleanup")
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream request count = %d, want 1; cleanup should not retry", got)
	}
}

func writeTestCA(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	tmpDir := t.TempDir()
	ca, err := cert.NewCaBuilder().
		Subject(pkix.Name{CommonName: "example.ca.test"}).
		ValidateDays(1).
		Build()
	if err != nil {
		t.Fatal(err)
	}
	keyPem, certPem := ca.Pem()
	certPath = filepath.Join(tmpDir, "ca.crt")
	keyPath = filepath.Join(tmpDir, "ca.key")
	if err := os.WriteFile(certPath, certPem, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0644); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
