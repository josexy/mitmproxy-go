package mitmproxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/websocket"
	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
)

const lifecycleWait = 3 * time.Second

const websocketUpgradeHeaders = "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"

func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

// startFixedBodyOrigin answers every request on every connection with body.
func startFixedBodyOrigin(t *testing.T, body string) string {
	t.Helper()
	listener := listenLoopback(t)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					request, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					_, _ = io.Copy(io.Discard, request.Body)
					if _, err := fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body); err != nil {
						return
					}
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// startSilentOrigin accepts one connection, reads one request and never
// answers. received closes when the request arrives and closed closes when the
// proxy closes the connection.
func startSilentOrigin(t *testing.T) (addr string, received, closed <-chan struct{}) {
	t.Helper()
	listener := listenLoopback(t)
	receivedCh, closedCh := make(chan struct{}), make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		if _, err := http.ReadRequest(reader); err != nil {
			return
		}
		close(receivedCh)
		_, _ = io.Copy(io.Discard, reader)
		close(closedCh)
	}()
	return listener.Addr().String(), receivedCh, closedCh
}

func waitClosed(t *testing.T, closed <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-closed:
	case <-time.After(lifecycleWait):
		t.Fatalf("%s was not closed within %v", what, lifecycleWait)
	}
}

func startSOCKS5Proxy(t *testing.T, opt ...Option) string {
	t.Helper()
	certPath, keyPath := writeTestCA(t)
	handler, err := NewMitmProxyHandler(append([]Option{WithCACertPath(certPath), WithCAKeyPath(keyPath)}, opt...)...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Cleanup)
	listener := listenLoopback(t)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _ = handler.ServeSOCKS5(context.Background(), conn) }()
		}
	}()
	return listener.Addr().String()
}

func dialSOCKS5(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		t.Fatal(err)
	}
	request := append([]byte{5, 1, 0, 1}, net.ParseIP(host).To4()...)
	request = binary.BigEndian.AppendUint16(request, uint16(port))
	if _, err := conn.Write(request); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil || reply[1] != socks5ReplySucceeded {
		t.Fatalf("SOCKS5 reply = %v, %v", reply, err)
	}
	return conn
}

func TestWebsocketRejectedUpgradeIsForwardedWithBody(t *testing.T) {
	listener := listenLoopback(t)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nX-Reason: token\r\nContent-Type: text/plain\r\nContent-Length: 6\r\n\r\ndenied")
		time.Sleep(lifecycleWait)
	}()
	upstream := listener.Addr().String()
	var intercepted atomic.Bool
	proxy := startKeepAliveProxy(t, WithDisableProxy(), WithWebsocketInterceptor(
		func(context.Context, *http.Request, *http.Response, WebsocketFramesWatcher) { intercepted.Store(true) }))
	conn, reader := dialProxy(t, proxy)
	if _, err := fmt.Fprintf(conn, "GET http://%s/ws HTTP/1.1\r\nHost: %s\r\n%s\r\n", upstream, upstream, websocketUpgradeHeaders); err != nil {
		t.Fatal(err)
	}
	response, body := readProxyResponse(t, reader, http.MethodGet)
	if response.StatusCode != http.StatusForbidden || body != "denied" || response.Header.Get("X-Reason") != "token" {
		t.Fatalf("response = %d %q X-Reason=%q; want 403 denied token", response.StatusCode, body, response.Header.Get("X-Reason"))
	}
	if !response.Close {
		t.Fatal("rejected upgrade did not close the client connection")
	}
	if intercepted.Load() {
		t.Fatal("WebSocket interceptor ran for a rejected upgrade")
	}
}

// An upgrade that fails on a freshly dialed upstream connection must close it.
func TestWebsocketFailedUpgradeClosesDialedUpstream(t *testing.T) {
	listener := listenLoopback(t)
	upgradeConnClosed := make(chan struct{})
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					request, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					if isWSUpgrade(request.Header) {
						_, _ = io.WriteString(conn, "not an http response\r\n\r\n")
						_, _ = io.Copy(io.Discard, reader)
						close(upgradeConnClosed)
						return
					}
					_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
				}
			}()
		}
	}()
	upstream := listener.Addr().String()
	proxy := startKeepAliveProxy(t, WithDisableProxy())
	conn, reader := dialProxy(t, proxy)
	// The first request hands the tunnel's upstream connection to the
	// transport, so the upgrade dials a connection of its own.
	if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
		t.Fatal(err)
	}
	readProxyResponse(t, reader, http.MethodGet)
	if _, err := fmt.Fprintf(conn, "GET http://%s/ws HTTP/1.1\r\nHost: %s\r\n%s\r\n", upstream, upstream, websocketUpgradeHeaders); err != nil {
		t.Fatal(err)
	}
	waitClosed(t, upgradeConnClosed, "upstream connection dialed for a failed upgrade")
}

func TestWebsocketUpstreamHandshakeIsBounded(t *testing.T) {
	upstream, received, closed := startSilentOrigin(t)
	proxy := startKeepAliveProxy(t, WithDisableProxy(), WithHandshakeTimeout(200*time.Millisecond))
	conn, reader := dialProxy(t, proxy)
	if _, err := fmt.Fprintf(conn, "GET http://%s/ws HTTP/1.1\r\nHost: %s\r\n%s\r\n", upstream, upstream, websocketUpgradeHeaders); err != nil {
		t.Fatal(err)
	}
	receiveRegressionValue(t, received)
	waitClosed(t, closed, "upstream connection with an unanswered upgrade")
	_ = conn.SetReadDeadline(time.Now().Add(lifecycleWait))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("client received data for an upgrade that timed out")
	}
}

func TestWebsocketInterceptorSkipsPassthroughHost(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Upgrade(w, r, nil, 0, 0)
		if err != nil {
			return
		}
		defer conn.Close()
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(messageType, data); err != nil {
				return
			}
		}
	}))
	t.Cleanup(origin.Close)
	upstream := origin.Listener.Addr().String()
	_, port, err := net.SplitHostPort(startFixedBodyOrigin(t, "ok"))
	if err != nil {
		t.Fatal(err)
	}
	interceptedHost := net.JoinHostPort("localhost", port)
	var intercepted atomic.Bool
	proxy := startKeepAliveProxy(t, WithDisableProxy(), WithExcludeHosts("127.0.0.1"), WithWebsocketInterceptor(
		func(_ context.Context, _ *http.Request, _ *http.Response, watcher WebsocketFramesWatcher) {
			intercepted.Store(true)
			for frame := range watcher.Receive() {
				_ = frame.Invoke()
			}
		}))
	conn, reader := dialProxy(t, proxy)
	// Start with an intercepted origin so the upgrade to the excluded host is
	// a keep-alive request that the proxy parses itself.
	if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", interceptedHost, interceptedHost); err != nil {
		t.Fatal(err)
	}
	readProxyResponse(t, reader, http.MethodGet)
	if _, err := fmt.Fprintf(conn, "GET http://%s/ws HTTP/1.1\r\nHost: %s\r\n%s\r\n", upstream, upstream, websocketUpgradeHeaders); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d; want 101", response.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	if intercepted.Load() {
		t.Fatal("WebSocket interceptor ran for an excluded host")
	}
}

// Excluding the first origin of a plain proxy connection must not route later
// requests on that connection to it.
func TestPlainProxyPassthroughDoesNotPinLaterRequests(t *testing.T) {
	excluded := startFixedBodyOrigin(t, "excluded")
	intercepted := startFixedBodyOrigin(t, "intercepted")
	_, port, err := net.SplitHostPort(excluded)
	if err != nil {
		t.Fatal(err)
	}
	excludedHost := net.JoinHostPort("localhost", port)
	proxy := startKeepAliveProxy(t, WithDisableProxy(), WithExcludeHosts("localhost"),
		WithHTTPInterceptor(func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
			response, err := next.Invoke(req)
			if err == nil {
				response.Header.Set("X-Intercepted", "yes")
			}
			return response, err
		}))
	conn, reader := dialProxy(t, proxy)
	for _, want := range []struct{ host, body, intercepted string }{
		{excludedHost, "excluded", ""},
		{intercepted, "intercepted", "yes"},
		{excludedHost, "excluded", ""},
	} {
		if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", want.host, want.host); err != nil {
			t.Fatal(err)
		}
		response, body := readProxyResponse(t, reader, http.MethodGet)
		if body != want.body || response.Header.Get("X-Intercepted") != want.intercepted {
			t.Fatalf("%s: body=%q X-Intercepted=%q; want %q %q", want.host, body, response.Header.Get("X-Intercepted"), want.body, want.intercepted)
		}
	}
}

// startRawSinkOrigin accepts one connection, reads it to EOF and then keeps
// writing to it without ever closing it, so only the proxy can end the
// connection. received carries what was read, and closed closes once a write
// fails because the proxy closed the connection.
func startRawSinkOrigin(t *testing.T) (addr string, received <-chan string, closed <-chan struct{}) {
	t.Helper()
	listener := listenLoopback(t)
	receivedCh, closedCh := make(chan string, 1), make(chan struct{})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		receivedCh <- string(data)
		for {
			if _, err := conn.Write([]byte("late")); err != nil {
				close(closedCh)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()
	return listener.Addr().String(), receivedCh, closedCh
}

// A client that closes or half-closes a raw tunnel ends it: its data reaches
// upstream, and then the upstream connection closes at once, even though the
// upstream server would keep it open.
func TestRawTunnelClientCloseClosesUpstream(t *testing.T) {
	const payload = "\x00\x01binary"
	for _, socks := range []bool{false, true} {
		for _, mode := range []struct {
			name string
			end  func(*net.TCPConn) error
		}{
			{"close", (*net.TCPConn).Close},
			{"half-close", (*net.TCPConn).CloseWrite},
		} {
			entry := "connect"
			if socks {
				entry = "socks5"
			}
			t.Run(entry+"/"+mode.name, func(t *testing.T) {
				upstream, received, closed := startRawSinkOrigin(t)
				var conn net.Conn
				var reader *bufio.Reader
				if socks {
					conn = dialSOCKS5(t, startSOCKS5Proxy(t, WithDisableProxy()), upstream)
					reader = bufio.NewReader(conn)
				} else {
					conn, reader = dialProxy(t, startKeepAliveProxy(t, WithDisableProxy()))
					if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
						t.Fatal(err)
					}
					readConnectResponse(t, reader)
				}
				if _, err := io.WriteString(conn, payload); err != nil {
					t.Fatal(err)
				}
				if err := mode.end(conn.(*net.TCPConn)); err != nil {
					t.Fatal(err)
				}
				if got := receiveRegressionValue(t, received); got != payload {
					t.Fatalf("upstream received %q; want %q", got, payload)
				}
				waitClosed(t, closed, "upstream connection of a client that ended a raw tunnel")
				if mode.name == "half-close" {
					// The tunnel is gone, so nothing upstream sends afterwards
					// reaches the client.
					_ = conn.SetReadDeadline(time.Now().Add(lifecycleWait))
					if data, err := io.ReadAll(reader); err != nil || len(data) != 0 {
						t.Fatalf("client read %q, %v after ending the tunnel; want EOF", data, err)
					}
				}
			})
		}
	}
}

// An upstream server that shuts down its sending side is relayed gracefully:
// the client reads every byte and then EOF, and its own data still reaches
// upstream until it closes.
func TestRawTunnelForwardsUpstreamHalfClose(t *testing.T) {
	const payload = "\x00\x01binary"
	listener := listenLoopback(t)
	serverGot := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, request); err != nil {
			serverGot <- "read request: " + err.Error()
			return
		}
		_, _ = io.WriteString(conn, "reply")
		_ = conn.(*net.TCPConn).CloseWrite()
		rest, _ := io.ReadAll(conn)
		serverGot <- string(rest)
	}()
	upstream := listener.Addr().String()
	proxy := startKeepAliveProxy(t, WithDisableProxy())
	conn, reader := dialProxy(t, proxy)
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
		t.Fatal(err)
	}
	readConnectResponse(t, reader)
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(reader)
	if err != nil || string(reply) != "reply" {
		t.Fatalf("reply = %q, %v; want reply then EOF", reply, err)
	}
	if _, err := io.WriteString(conn, "more"); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if got := receiveRegressionValue(t, serverGot); got != "more" {
		t.Fatalf("upstream received %q after its half-close; want more", got)
	}
}

// A self-signed upstream leaf commonly carries CA:TRUE and must still be
// mirrored instead of failing the handshake.
func TestSelfSignedCALeafUpstreamIsMirrored(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "self-signed.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"self-signed.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener := tls.NewListener(listenLoopback(t), &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := http.ReadRequest(bufio.NewReader(conn)); err != nil {
			return
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
	}()
	upstream := listener.Addr().String()
	proxy := startKeepAliveProxy(t, WithDisableProxy(), WithSkipVerifySSLFromServer())
	conn, reader := dialProxy(t, proxy)
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
		t.Fatal(err)
	}
	readConnectResponse(t, reader)
	client := tls.Client(&bufConnExt{Conn: conn, Reader: reader}, &tls.Config{InsecureSkipVerify: true, ServerName: "self-signed.test"})
	if err := client.Handshake(); err != nil {
		t.Fatalf("downstream handshake: %v", err)
	}
	if names := client.ConnectionState().PeerCertificates[0].DNSNames; !slices.Contains(names, "self-signed.test") {
		t.Fatalf("mirrored DNS names = %v; want self-signed.test", names)
	}
	// The tunnel is pinned to the CONNECT authority, so the request names it.
	if _, err := fmt.Fprintf(client, "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", upstream); err != nil {
		t.Fatal(err)
	}
	response, body := readProxyResponse(t, bufio.NewReader(client), http.MethodGet)
	if response.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("response = %d %q; want 200 ok", response.StatusCode, body)
	}
}

type proxyEntryPoint struct {
	name  string
	depth int
	socks bool
}

var proxyEntryPoints = []proxyEntryPoint{
	{"socks5 serial", 1, true},
	{"socks5 pipelined", 8, true},
	{"plain proxy serial", 1, false},
	{"plain proxy pipelined", 8, false},
}

// connectThroughProxy starts a proxy with opt and returns a client connection
// whose next request is read by the proxy itself. SOCKS5 connects to target; a
// plain proxy connection first exchanges one request with another origin,
// because the HTTP server rather than the proxy reads the first request.
func connectThroughProxy(t *testing.T, entry proxyEntryPoint, target string, opt ...Option) (*net.TCPConn, *bufio.Reader) {
	t.Helper()
	opt = append([]Option{WithDisableProxy(), WithHTTP1PipelineDepth(entry.depth)}, opt...)
	if entry.socks {
		conn := dialSOCKS5(t, startSOCKS5Proxy(t, opt...), target)
		return conn.(*net.TCPConn), bufio.NewReader(conn)
	}
	answered := startFixedBodyOrigin(t, "ok")
	conn, reader := dialProxy(t, startKeepAliveProxy(t, opt...))
	if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", answered, answered); err != nil {
		t.Fatal(err)
	}
	readProxyResponse(t, reader, http.MethodGet)
	return conn.(*net.TCPConn), reader
}

// A client that goes away while upstream has not answered must release the
// upstream connection at once, for every entry point and pipeline depth. A
// half-close looks the same to the proxy as a close, so it counts as one.
func TestClientDisconnectCancelsPendingExchange(t *testing.T) {
	for _, entry := range proxyEntryPoints {
		for _, mode := range []struct {
			name       string
			disconnect func(*net.TCPConn) error
		}{
			{"close", (*net.TCPConn).Close},
			{"half-close", (*net.TCPConn).CloseWrite},
			{"reset", func(conn *net.TCPConn) error {
				// A zero linger time makes Close send a reset instead of a FIN.
				if err := conn.SetLinger(0); err != nil {
					return err
				}
				return conn.Close()
			}},
		} {
			t.Run(entry.name+"/"+mode.name, func(t *testing.T) {
				upstream, received, closed := startSilentOrigin(t)
				conn, _ := connectThroughProxy(t, entry, upstream)
				if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
					t.Fatal(err)
				}
				receiveRegressionValue(t, received)
				if err := mode.disconnect(conn); err != nil {
					t.Fatal(err)
				}
				waitClosed(t, closed, "upstream connection of a departed client")
			})
		}
	}
}

// startOpaqueUpgradeOrigin answers ordinary requests with "ok" and switches a
// request for `Upgrade: tcp` to an echo of the raw stream. A request that
// arrives without the upgrade headers, with proxy credentials, or with the
// wrong body is answered 400 with the reason.
func startOpaqueUpgradeOrigin(t *testing.T) string {
	t.Helper()
	listener := listenLoopback(t)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					request, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					body, err := io.ReadAll(request.Body)
					if err != nil {
						return
					}
					if request.URL.Path != "/attach" {
						if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
							return
						}
						continue
					}
					var problem string
					switch {
					case request.Header.Get("Upgrade") != "tcp" || !strings.EqualFold(request.Header.Get("Connection"), "Upgrade"):
						problem = "upgrade headers missing"
					case request.Header.Get("Proxy-Authorization") != "":
						problem = "proxy credentials forwarded"
					case string(body) != "body":
						problem = fmt.Sprintf("body %q", body)
					}
					if problem != "" {
						_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: %d\r\n\r\n%s", len(problem), problem)
						return
					}
					if _, err := io.WriteString(conn, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n"); err != nil {
						return
					}
					_, _ = io.Copy(conn, reader)
					return
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// An upgrade to a protocol other than WebSocket reaches a passthrough host as
// sent, minus proxy credentials, and the connection is relayed raw afterwards.
func TestPlainProxyPassthroughForwardsOpaqueUpgrade(t *testing.T) {
	for _, test := range []struct {
		name      string
		depth     int
		keepAlive bool
	}{
		{"first request serial", 1, false},
		{"first request pipelined", 8, false},
		{"keep-alive request serial", 1, true},
		{"keep-alive request pipelined", 8, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			upstream := startOpaqueUpgradeOrigin(t)
			proxy := startKeepAliveProxy(t, WithDisableProxy(), WithExcludeHosts("127.0.0.1"), WithHTTP1PipelineDepth(test.depth))
			conn, reader := dialProxy(t, proxy)
			if test.keepAlive {
				if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
					t.Fatal(err)
				}
				if _, body := readProxyResponse(t, reader, http.MethodGet); body != "ok" {
					t.Fatalf("keep-alive body = %q; want ok", body)
				}
			}
			if _, err := fmt.Fprintf(conn, "POST http://%s/attach HTTP/1.1\r\nHost: %s\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nProxy-Authorization: Basic c2VjcmV0\r\nContent-Length: 4\r\n\r\nbody", upstream, upstream); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodPost})
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusSwitchingProtocols {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("response = %d %q; want 101", response.StatusCode, body)
			}
			if _, err := io.WriteString(conn, "ping"); err != nil {
				t.Fatal(err)
			}
			echo := make([]byte, 4)
			if _, err := io.ReadFull(reader, echo); err != nil || string(echo) != "ping" {
				t.Fatalf("echo = %q, %v; want ping", echo, err)
			}
		})
	}
}

type blockingTargetDialer struct {
	target   string
	canceled chan struct{}
}

func (d *blockingTargetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if addr != d.target {
		var dialer net.Dialer
		return dialer.DialContext(ctx, network, addr)
	}
	select {
	case <-ctx.Done():
		close(d.canceled)
		return nil, ctx.Err()
	case <-time.After(10 * time.Second):
		return nil, errors.New("blocked dial was never canceled")
	}
}

// Cleanup must interrupt an upstream dial instead of waiting for it to time out.
func TestCleanupInterruptsPendingUpstreamDial(t *testing.T) {
	answered := startFixedBodyOrigin(t, "ok")
	const blocked = "192.0.2.1:80"
	dialer := &blockingTargetDialer{target: blocked, canceled: make(chan struct{})}
	certPath, keyPath := writeTestCA(t)
	handler, err := NewMitmProxyHandler(WithCACertPath(certPath), WithCAKeyPath(keyPath),
		WithDisableProxy(), WithContextDialer(dialer), WithHTTP1PipelineDepth(1))
	if err != nil {
		t.Fatal(err)
	}
	listener := listenLoopback(t)
	server := &http.Server{Handler: handler}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()

	conn, reader := dialProxy(t, listener)
	if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", answered, answered); err != nil {
		t.Fatal(err)
	}
	readProxyResponse(t, reader, http.MethodGet)
	if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: 192.0.2.1\r\n\r\n", blocked); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	start := time.Now()
	handler.Cleanup()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Cleanup took %v waiting for a pending dial", elapsed)
	}
	waitClosed(t, dialer.canceled, "pending upstream dial")
}

// Re-invoking upstream while an earlier response body is still open must not
// wait behind that body, and the discarded body must be released afterwards so
// the connection remains usable.
func TestInterceptorReinvokeWithOpenBodyGetsResponse(t *testing.T) {
	upstream := startFixedBodyOrigin(t, "ok")
	proxy := startKeepAliveProxy(t, WithDisableProxy(), WithHTTPInterceptor(
		func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
			if _, err := next.Invoke(req); err != nil { // discarded without Close
				return nil, err
			}
			return next.Invoke(req.Clone(ctx))
		}))
	conn, reader := dialProxy(t, proxy)
	for range 2 {
		if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", upstream, upstream); err != nil {
			t.Fatal(err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(lifecycleWait))
		response, body := readProxyResponse(t, reader, http.MethodGet)
		if response.StatusCode != http.StatusOK || body != "ok" {
			t.Fatalf("response = %d %q; want 200 ok", response.StatusCode, body)
		}
	}
}
