package mitmproxy

import (
	"context"
	"net"
	"testing"
	"time"

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
