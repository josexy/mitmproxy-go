package mitmproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josexy/mitmproxy-go/v2/metadata"
	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptest"
)

func TestIPTunnelDomainAuthority(t *testing.T) {
	caCert, caKey, serverCert, serverKey := writeTestCertificates(t, t.TempDir())
	certificate, err := tls.LoadX509KeyPair(serverCert, serverKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caCert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		t.Fatal("load downstream CA")
	}
	for _, entry := range []string{"connect", "socks5", "serve"} {
		for _, protocol := range []string{"http1", "http1-pipeline", "h2"} {
			for _, mode := range []string{"tls", "tls-no-sni", "cleartext"} {
				t.Run(entry+"/"+protocol+"/"+mode, func(t *testing.T) {
					streamCanceled := make(chan struct{})
					var requests atomic.Int32
					origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						requests.Add(1)
						if mode != "cleartext" {
							wantSNI := "localhost"
							if mode == "tls-no-sni" {
								wantSNI = ""
							}
							if req.TLS == nil || req.TLS.ServerName != wantSNI {
								t.Errorf("upstream TLS = %#v; want SNI %q", req.TLS, wantSNI)
							}
						}
						if req.URL.Path == "/stream" {
							_, _ = io.WriteString(w, "ready")
							w.(http.Flusher).Flush()
							<-req.Context().Done()
							close(streamCanceled)
							return
						}
						_, _ = io.WriteString(w, req.Host+req.URL.Path)
					}))
					if mode == "cleartext" {
						protocols := &http.Protocols{}
						protocols.SetHTTP1(true)
						protocols.SetUnencryptedHTTP2(protocol == "h2")
						origin.Config.Protocols = protocols
						origin.Start()
					} else {
						origin.EnableHTTP2 = protocol == "h2"
						origin.TLS = &tls.Config{Certificates: []tls.Certificate{certificate}}
						origin.StartTLS()
					}
					t.Cleanup(origin.Close)
					target := origin.Listener.Addr().String()
					ip, port, err := net.SplitHostPort(target)
					if err != nil {
						t.Fatal(err)
					}
					authority := net.JoinHostPort("localhost", port)
					depth := 1
					if protocol == "http1-pipeline" {
						depth = 4
					}
					var dials atomic.Int32
					tunnel := dialAuthorityTestTunnel(t, entry, target,
						WithCACertPath(caCert), WithCAKeyPath(caKey), WithRootCAs(serverCert),
						WithHTTP1PipelineDepth(depth),
						WithContextDialer(testContextDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
							if addr != target {
								return nil, fmt.Errorf("dial target changed to %q; want %q", addr, target)
							}
							dials.Add(1)
							return (&net.Dialer{}).DialContext(ctx, network, addr)
						})),
						WithHTTPInterceptor(func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
							reqCtx, _ := FromRequestContext(ctx)
							md, _ := metadata.FromContext(ctx)
							recordedTarget := md.MD().RequestHostport
							if reqCtx.Hostport != target || recordedTarget != target {
								t.Errorf("request or metadata target changed: %q, %q", reqCtx.Hostport, recordedTarget)
							}
							return next.Invoke(req)
						}),
					)
					scheme := "http"
					if mode != "cleartext" {
						scheme = "https"
						serverName, alpn := "localhost", "http/1.1"
						if mode == "tls-no-sni" {
							serverName = ip // TLS verifies the IP certificate without sending SNI.
						}
						if protocol == "h2" {
							alpn = "h2"
						}
						client := tls.Client(tunnel, &tls.Config{ServerName: serverName, RootCAs: roots, NextProtos: []string{alpn}})
						t.Cleanup(func() { _ = client.Close() })
						if err := client.Handshake(); err != nil {
							t.Fatal(err)
						}
						if got := client.ConnectionState().NegotiatedProtocol; got != alpn {
							t.Fatalf("ALPN = %q; want %q", got, alpn)
						}
						tunnel = client
					}
					reader := bufio.NewReader(tunnel)
					var h2 *singleUseHTTP2Transport
					if protocol == "h2" {
						h2 = newSingleUseHTTP2Transport(t, tunnel)
					}
					send := func(host, path string) *http.Response {
						t.Helper()
						if h2 != nil {
							req, err := http.NewRequest(http.MethodGet, scheme+"://"+host+path, nil)
							if err != nil {
								t.Fatal(err)
							}
							response, err := h2.RoundTrip(req)
							if err != nil {
								t.Fatal(err)
							}
							return response
						}
						if _, err := fmt.Fprintf(tunnel, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, host); err != nil {
							t.Fatal(err)
						}
						response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
						if err != nil {
							t.Fatal(err)
						}
						return response
					}
					check := func(response *http.Response, status int, body string) {
						t.Helper()
						defer response.Body.Close()
						got, err := io.ReadAll(response.Body)
						if err != nil {
							t.Fatal(err)
						}
						if response.StatusCode != status || (status == http.StatusOK && string(got) != body) {
							t.Fatalf("response = %d %q; want %d %q", response.StatusCode, got, status, body)
						}
					}
					// Send both HTTP/1 requests before reading to exercise pipeline order.
					if h2 == nil {
						for _, path := range []string{"/first", "/second"} {
							if _, err := fmt.Fprintf(tunnel, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", path, authority); err != nil {
								t.Fatal(err)
							}
						}
					}
					for _, path := range []string{"/first", "/second"} {
						var response *http.Response
						if h2 != nil {
							response = send(authority, path)
						} else {
							response, err = http.ReadResponse(reader, &http.Request{Method: http.MethodGet})
							if err != nil {
								t.Fatal(err)
							}
						}
						check(response, http.StatusOK, authority+path)
					}
					if dials.Load() != 1 {
						t.Fatalf("same-origin requests made %d upstream dials; want 1", dials.Load())
					}
					if h2 == nil {
						// Close the idle upstream without asking downstream to close.
						origin.CloseClientConnections()
						check(send(authority, "/after"), http.StatusOK, authority+"/after")
						if dials.Load() != 2 {
							t.Fatalf("upstream close made %d dials; want 2", dials.Load())
						}
						check(send(net.JoinHostPort("other.test", port), "/bad"), http.StatusMisdirectedRequest, "")
						if requests.Load() != 3 {
							t.Fatalf("origin received %d requests; want 3", requests.Load())
						}
					} else {
						stream := send(authority, "/stream")
						defer stream.Body.Close()
						prefix := make([]byte, 5)
						if _, err := io.ReadFull(stream.Body, prefix); err != nil || string(prefix) != "ready" {
							t.Fatalf("stream prefix = %q, %v", prefix, err)
						}
						check(send(net.JoinHostPort("other.test", port), "/bad"), http.StatusMisdirectedRequest, "")
						check(send("localhost:1", "/bad-port"), http.StatusMisdirectedRequest, "")
						select {
						case <-streamCanceled:
							t.Fatal("421 canceled a sibling stream")
						default:
						}
						_ = stream.Body.Close()
						select {
						case <-streamCanceled:
						case <-time.After(5 * time.Second):
							t.Fatal("closing stream body did not cancel upstream")
						}
						check(send(authority, "/after"), http.StatusOK, authority+"/after")
						check(send(target, "/ip"), http.StatusOK, target+"/ip")
						if requests.Load() != 5 || dials.Load() != 1 {
							t.Fatalf("origin requests = %d, dials = %d; want 5 and 1", requests.Load(), dials.Load())
						}
					}
				})
			}
		}
	}
}

// dialAuthorityTestTunnel exercises the public entry points over loopback TCP.
// Cleanup closes both sides and waits for the serving goroutine to exit.
func dialAuthorityTestTunnel(t *testing.T, entry, target string, options ...Option) net.Conn {
	t.Helper()
	options = append(options, WithDisableProxy(), WithHandshakeTimeout(5*time.Second), WithErrorHandler(func(ErrorContext) {}))
	handler, err := NewMitmProxyHandler(options...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(handler.Cleanup)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	var server *http.Server
	if entry == "connect" {
		server = &http.Server{Handler: handler}
		go func() { defer close(done); _ = server.Serve(listener) }()
	} else {
		go func() {
			defer close(done)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if entry == "socks5" {
				_ = handler.ServeSOCKS5(ctx, conn)
			} else {
				_ = handler.Serve(AppendToRequestContext(ctx, ReqContext{Hostport: target}), conn)
			}
		}()
	}
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		if server != nil {
			_ = server.Close()
		}
		handler.Cleanup()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("proxy did not stop")
		}
	})
	var conn net.Conn
	if entry == "serve" {
		conn, err = net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	} else {
		scheme := "http"
		if entry == "socks5" {
			scheme = "socks5"
		}
		dialCtx, cancelDial := context.WithTimeout(ctx, 5*time.Second)
		defer cancelDial()
		conn, err = NewProxyDialer(&url.URL{Scheme: scheme, Host: listener.Addr().String()}, nil).DialContext(dialCtx, "tcp", target)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestPlainProxyRetargetsFromIPToDomainOnSamePort(t *testing.T) {
	for _, depth := range []int{1, 4} {
		t.Run(fmt.Sprintf("depth-%d", depth), func(t *testing.T) {
			first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "first") }))
			t.Cleanup(first.Close)
			second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "second") }))
			t.Cleanup(second.Close)
			firstAddr := strings.TrimPrefix(first.URL, "http://")
			_, port, err := net.SplitHostPort(firstAddr)
			if err != nil {
				t.Fatal(err)
			}
			domainAddr := net.JoinHostPort("second.test", port)
			proxy := startKeepAliveProxy(t, WithDisableProxy(), WithHTTP1PipelineDepth(depth),
				WithContextDialer(testContextDialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
					if addr == domainAddr {
						addr = strings.TrimPrefix(second.URL, "http://")
					}
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				})))
			conn, reader := dialProxy(t, proxy)
			for _, request := range []struct{ target, want string }{{firstAddr, "first"}, {domainAddr, "second"}, {firstAddr, "first"}} {
				if _, err := fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", request.target, request.target); err != nil {
					t.Fatal(err)
				}
				response, body := readProxyResponse(t, reader, http.MethodGet)
				if response.StatusCode != http.StatusOK || body != request.want {
					t.Fatalf("target %s: response = %d %q; want %q", request.target, response.StatusCode, body, request.want)
				}
			}
		})
	}
}
