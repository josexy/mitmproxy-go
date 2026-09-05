package mitmproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	http "github.com/josexy/xhttp"
	utls "github.com/refraction-networking/utls"
)

type http2E2EObservation struct {
	fingerprint       http.Fingerprint
	fields            []string
	interceptorHeader string
	bodyIsNoBody      bool
	err               error
}

type http2E2EInterceptorContextKey struct{}

func TestHTTP2UpstreamExchangeTimingThroughProxy(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, serverCertPath, _ := writeTestCertificates(t, dir)
	originAddr := startH2CWireOrigin(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, "timed h2 response")
	}))

	events := make(chan HTTPExchangeTimingEvent, 4)
	observerAvailable := make(chan bool, 1)
	interceptor := func(ctx context.Context, request *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		observerAvailable <- ObserveHTTPExchangeTiming(ctx, func(event HTTPExchangeTimingEvent) {
			events <- event
		})
		return next.Invoke(request)
	}
	proxyAddr, proxyErrors := startHTTP2E2EProxy(
		t,
		caCertPath,
		caKeyPath,
		serverCertPath,
		interceptor,
		WithUpstreamHTTPTrace(),
	)

	tunnel := connectProxyTunnel(t, proxyAddr, originAddr)
	transport := newSingleUseHTTP2Transport(t, tunnel)
	request := newOrderedHTTP2Request(t, "http://"+originAddr+"/timing", testHTTP2E2EFingerprint(t))
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()

	select {
	case available := <-observerAvailable:
		if !available {
			t.Fatal("HTTP/2 timing observer was unavailable")
		}
	case <-time.After(time.Second):
		t.Fatal("HTTP/2 interceptor was not called")
	}
	want := []HTTPExchangeTimingPhase{
		HTTPExchangeRequestStarted,
		HTTPExchangeRequestEnded,
		HTTPExchangeResponseStarted,
		HTTPExchangeResponseEnded,
	}
	for index, phase := range want {
		select {
		case event := <-events:
			if event.Phase != phase || event.Attempt != 1 || event.Timestamp.IsZero() {
				t.Fatalf("event %d = %#v, want phase %s attempt 1", index, event, phase)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for event %s", phase)
		}
	}
	assertNoHTTP2E2EError(t, proxyErrors)
}

func TestHTTP2WireProfileThroughProxyEndToEnd(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, serverCertPath, _ := writeTestCertificates(t, dir)
	fingerprint := testHTTP2E2EFingerprint(t)
	expectedFingerprint := fingerprint

	originObserved := make(chan http2E2EObservation, 1)
	originAddr := startH2CWireOrigin(t, orderedHTTP2OriginHandler(originObserved, "through-proxy"))
	interceptorObserved := make(chan http2E2EObservation, 1)
	proxyAddr, proxyErrors := startHTTP2E2EProxy(
		t,
		caCertPath,
		caKeyPath,
		serverCertPath,
		observingHTTP2Interceptor(interceptorObserved),
	)

	tunnel := connectProxyTunnel(t, proxyAddr, originAddr)
	transport := newSingleUseHTTP2Transport(t, tunnel)
	request := newOrderedHTTP2Request(t, "http://"+originAddr+"/wire-profile", fingerprint)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	assertOrderedHTTP2Response(t, response, "through-proxy")

	assertHTTP2E2EObservation(t, receiveHTTP2Observation(t, interceptorObserved), expectedFingerprint, false)
	assertHTTP2E2EObservation(t, receiveHTTP2Observation(t, originObserved), expectedFingerprint, true)
	assertNoHTTP2E2EError(t, proxyErrors)
}

func TestHTTP2NonRootHeaderPriorityDoesNotCollideAcrossProxy(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, serverCertPath, _ := writeTestCertificates(t, dir)

	originObserved := make(chan http2E2EObservation, 1)
	originAddr := startH2CWireOrigin(t, orderedHTTP2OriginHandler(originObserved, "forwarded"))
	interceptorObserved := make(chan http2E2EObservation, 1)
	observeForwarded := observingHTTP2Interceptor(interceptorObserved)
	interceptor := func(ctx context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		if req.URL.Path == "/local" {
			return &http.Response{
				Status:        "204 No Content",
				StatusCode:    http.StatusNoContent,
				Proto:         "HTTP/2.0",
				ProtoMajor:    2,
				Header:        make(http.Header),
				Body:          http.NoBody,
				ContentLength: 0,
				Request:       req,
			}, nil
		}
		return observeForwarded(ctx, req, next)
	}
	proxyAddr, proxyErrors := startHTTP2E2EProxy(
		t,
		caCertPath,
		caKeyPath,
		serverCertPath,
		interceptor,
	)

	tunnel := connectProxyTunnel(t, proxyAddr, originAddr)
	transport := newSingleUseHTTP2Transport(t, tunnel)
	localFingerprint := testHTTP2E2EFingerprint(t)
	localRequest := newOrderedHTTP2Request(t, "http://"+originAddr+"/local", localFingerprint)
	localResponse, err := transport.RoundTrip(localRequest)
	if err != nil {
		t.Fatal(err)
	}
	if localResponse.StatusCode != http.StatusNoContent {
		localResponse.Body.Close()
		t.Fatalf("local response status = %d; want 204", localResponse.StatusCode)
	}
	if err := localResponse.Body.Close(); err != nil {
		t.Fatal(err)
	}

	forwardedFingerprint := testHTTP2E2EFingerprint(t)
	forwardedFingerprint.HeaderPriority = &http.FingerprintHeaderPriority{
		StreamDep: 1,
		Exclusive: true,
		Weight:    101,
	}
	forwardedRequest := newOrderedHTTP2Request(
		t,
		"http://"+originAddr+"/forwarded",
		forwardedFingerprint,
	)
	forwardedResponse, err := transport.RoundTrip(forwardedRequest)
	if err != nil {
		t.Fatal(err)
	}
	if forwardedResponse.StatusCode != http.StatusOK {
		forwardedResponse.Body.Close()
		select {
		case proxyErr := <-proxyErrors:
			t.Fatalf("forwarded response status = %d; proxy error: %v", forwardedResponse.StatusCode, proxyErr)
		default:
			t.Fatalf("forwarded response status = %d; want 200", forwardedResponse.StatusCode)
		}
	}
	assertOrderedHTTP2Response(t, forwardedResponse, "forwarded")

	wantDownstream := forwardedFingerprint
	wantUpstream := wantDownstream
	wantUpstream.HeaderPriority = nil
	assertHTTP2E2EObservation(t, receiveHTTP2Observation(t, interceptorObserved), wantDownstream, false)
	assertHTTP2E2EObservation(t, receiveHTTP2Observation(t, originObserved), wantUpstream, true)
	assertNoHTTP2E2EError(t, proxyErrors)
}

func TestTLSHTTP2FingerprintThroughUTLSMitmEndToEnd(t *testing.T) {
	dir := t.TempDir()
	caCertPath, caKeyPath, serverCertPath, serverKeyPath := writeTestCertificates(t, dir)
	fingerprint := testHTTP2E2EFingerprint(t)
	expectedFingerprint := fingerprint

	originObserved := make(chan http2E2EObservation, 1)
	originAddr, upstreamClientHello, upstreamALPN := startTLSHTTP2WireOrigin(
		t,
		serverCertPath,
		serverKeyPath,
		orderedHTTP2OriginHandler(originObserved, "tls-through-proxy"),
	)
	interceptorObserved := make(chan http2E2EObservation, 1)
	proxyAddr, proxyErrors := startHTTP2E2EProxy(
		t,
		caCertPath,
		caKeyPath,
		serverCertPath,
		observingHTTP2Interceptor(interceptorObserved),
	)

	tunnel := connectProxyTunnel(t, proxyAddr, originAddr)
	captureConn := &writeCaptureConn{Conn: tunnel}
	spec, err := utls.UTLSIdToSpec(utls.HelloFirefox_120)
	if err != nil {
		t.Fatal(err)
	}
	downstream := utls.UClient(captureConn, &utls.Config{
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		NextProtos:         []string{http2NextProtoTLS, "http/1.1"},
	}, utls.HelloCustom)
	if err := downstream.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err := downstream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := downstream.Handshake(); err != nil {
		t.Fatal(err)
	}
	if err := downstream.SetDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := downstream.ConnectionState().NegotiatedProtocol; got != http2NextProtoTLS {
		t.Fatalf("downstream ALPN = %q; want %q", got, http2NextProtoTLS)
	}

	transport := newSingleUseHTTP2Transport(t, downstream)
	request := newOrderedHTTP2Request(t, "https://"+originAddr+"/tls-wire-profile", fingerprint)
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	assertOrderedHTTP2Response(t, response, "tls-through-proxy")

	assertMirroredClientHello(t, captureConn, receiveRawClientHello(t, upstreamClientHello))
	if got := receiveString(t, upstreamALPN); got != http2NextProtoTLS {
		t.Fatalf("upstream ALPN = %q; want %q", got, http2NextProtoTLS)
	}
	assertHTTP2E2EObservation(t, receiveHTTP2Observation(t, interceptorObserved), expectedFingerprint, false)
	assertHTTP2E2EObservation(t, receiveHTTP2Observation(t, originObserved), expectedFingerprint, true)
	assertNoHTTP2E2EError(t, proxyErrors)
}

func wireInitialFieldNames(req *http.Request) []string {
	for _, block := range RequestWireHeaderBlocks(req) {
		if block.Kind != http.HeaderBlockInitial {
			continue
		}
		fields := make([]string, 0, len(block.Fields))
		for _, field := range block.Fields {
			fields = append(fields, strings.ToLower(field.Name))
		}
		return fields
	}
	return nil
}

func http2ResponseFieldNames(resp *http.Response, kind http.HeaderBlockKind) []string {
	var fields []string
	for _, block := range http.ResponseHeaderBlocks(resp) {
		if block.Kind != kind {
			continue
		}
		fields = fields[:0]
		for _, field := range block.Fields {
			fields = append(fields, strings.ToLower(field.Name))
		}
	}
	return fields
}

func assertFieldPrefix(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) < len(want) || !slices.Equal(got[:len(want)], want) {
		t.Fatalf("field order = %v; want prefix %v", got, want)
	}
}

func startHTTP2E2EProxy(
	t *testing.T,
	caCertPath, caKeyPath, rootCertPath string,
	interceptor HTTPInterceptor,
	extraOptions ...Option,
) (string, <-chan error) {
	t.Helper()
	proxyErrors := make(chan error, 16)
	options := []Option{
		WithCACertPath(caCertPath),
		WithCAKeyPath(caKeyPath),
		WithRootCAs(rootCertPath),
		WithHTTPInterceptor(interceptor),
		WithErrorHandler(func(ec ErrorContext) {
			select {
			case proxyErrors <- ec.Error:
			default:
			}
		}),
	}
	options = append(options, extraOptions...)
	handler, err := NewMitmProxyHandler(options...)
	if err != nil {
		t.Fatal(err)
	}

	listener := listenLocalhostForFingerprintTest(t)
	server := &http.Server{Handler: handler}
	serveDone := make(chan error, 1)
	go func() {
		serveErr := server.Serve(listener)
		if errors.Is(serveErr, http.ErrServerClosed) || errors.Is(serveErr, net.ErrClosed) {
			serveErr = nil
		}
		serveDone <- serveErr
	}()

	t.Cleanup(func() {
		_ = server.Close()
		handler.Cleanup()
		select {
		case serveErr := <-serveDone:
			if serveErr != nil {
				t.Errorf("HTTP/2 E2E proxy server: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("HTTP/2 E2E proxy server did not stop")
		}
	})
	return listener.Addr().String(), proxyErrors
}

func startH2CWireOrigin(t *testing.T, handler http.Handler) string {
	t.Helper()
	listener := listenLocalhostForFingerprintTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serveDone <- err
			return
		}
		serveDone <- serveHTTP2Conn(ctx, conn, handler, nil, false)
	}()

	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case serveErr := <-serveDone:
			if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
				t.Errorf("h2c E2E origin: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("h2c E2E origin did not stop")
		}
	})
	return listener.Addr().String()
}

func startTLSHTTP2WireOrigin(
	t *testing.T,
	certPath, keyPath string,
	handler http.Handler,
) (string, <-chan []byte, <-chan string) {
	t.Helper()
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	listener := listenLocalhostForFingerprintTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	clientHello := make(chan []byte, 1)
	negotiatedALPN := make(chan string, 1)
	serveDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serveDone <- acceptErr
			return
		}
		captureConn := newClientHelloCaptureConn(conn)
		tlsConn := tls.Server(captureConn, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			NextProtos:   []string{http2NextProtoTLS},
		})
		handshakeCtx, cancelHandshake := context.WithTimeout(ctx, 5*time.Second)
		handshakeErr := tlsConn.HandshakeContext(handshakeCtx)
		cancelHandshake()
		if handshakeErr != nil {
			_ = tlsConn.Close()
			serveDone <- fmt.Errorf("origin TLS handshake: %w", handshakeErr)
			return
		}
		raw, captureErr := captureConn.RawClientHello()
		if captureErr != nil {
			_ = tlsConn.Close()
			serveDone <- fmt.Errorf("capture origin ClientHello: %w", captureErr)
			return
		}
		clientHello <- raw
		negotiatedALPN <- tlsConn.ConnectionState().NegotiatedProtocol
		serveDone <- serveHTTP2Conn(ctx, tlsConn, handler, nil, true)
	}()

	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		select {
		case serveErr := <-serveDone:
			if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) {
				t.Errorf("TLS HTTP/2 E2E origin: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Error("TLS HTTP/2 E2E origin did not stop")
		}
	})
	return listener.Addr().String(), clientHello, negotiatedALPN
}

func testHTTP2E2EFingerprint(t *testing.T) http.Fingerprint {
	t.Helper()
	const canonical = "1:65536;3:1000;4:6291456;6:262144|15663105|3:0:0:201,5:1:3:101|s,m,a,p"
	fingerprint, err := http.ParseFingerprint(canonical)
	if err != nil {
		t.Fatalf("parse HTTP/2 E2E fingerprint: %v", err)
	}
	fingerprint.HeaderPriority = &http.FingerprintHeaderPriority{
		StreamDep: 0,
		Exclusive: true,
		Weight:    101,
	}
	return fingerprint
}

type singleUseHTTP2Transport struct {
	mu         sync.Mutex
	conn       net.Conn
	clientConn *http.ClientConn
	used       bool
}

func newSingleUseHTTP2Transport(t *testing.T, conn net.Conn) *singleUseHTTP2Transport {
	t.Helper()
	transport := &singleUseHTTP2Transport{conn: conn}
	t.Cleanup(transport.Close)
	return transport
}

func (t *singleUseHTTP2Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	clientConn := t.clientConn
	if clientConn == nil {
		if t.used {
			t.mu.Unlock()
			return nil, errors.New("HTTP/2 E2E transport attempted a second dial")
		}
		t.used = true
		protocols := &http.Protocols{}
		protocols.SetUnencryptedHTTP2(true)
		dialed := false
		baseTransport := &http.Transport{
			DisableCompression: true,
			Protocols:          protocols,
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				if dialed {
					return nil, errors.New("HTTP/2 E2E transport attempted a second dial")
				}
				dialed = true
				return t.conn, nil
			},
		}
		var err error
		clientConn, err = baseTransport.NewClientConn(req.Context(), "http", req.URL.Host)
		if err != nil {
			t.mu.Unlock()
			return nil, err
		}
		t.clientConn = clientConn
	}
	t.mu.Unlock()
	return clientConn.RoundTrip(req)
}

func (t *singleUseHTTP2Transport) Close() {
	t.mu.Lock()
	clientConn := t.clientConn
	t.clientConn = nil
	conn := t.conn
	t.conn = nil
	t.mu.Unlock()
	if clientConn != nil {
		_ = clientConn.Close()
		return
	}
	if conn != nil {
		_ = conn.Close()
	}
}

func newOrderedHTTP2Request(t *testing.T, target string, fingerprint http.Fingerprint) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Zeta", "one")
	req.Header.Set("X-Alpha", "two")
	req.Header.Set("User-Agent", "mitmproxy-go-http2-e2e")
	req, err = http.WithRequestHeaderOrder(req, http.HeaderOrder{
		Headers: []string{"x-zeta", "x-alpha", "user-agent"},
	})
	if err != nil {
		t.Fatal(err)
	}
	req, err = http.WithRequestFingerprint(req, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func captureHTTP2E2EObservation(req *http.Request) http2E2EObservation {
	observation := http2E2EObservation{
		fields:            wireInitialFieldNames(req),
		interceptorHeader: req.Header.Get("X-Interceptor-Request"),
		bodyIsNoBody:      req.Body == http.NoBody,
	}
	fingerprint, ok := RequestHTTP2Fingerprint(req)
	if !ok {
		observation.err = errors.New("HTTP/2 request fingerprint missing")
		return observation
	}
	observation.fingerprint = fingerprint
	if len(observation.fields) == 0 {
		observation.err = errors.New("HTTP/2 initial request header block missing")
	}
	return observation
}

func observingHTTP2Interceptor(observed chan<- http2E2EObservation) HTTPInterceptor {
	return func(_ context.Context, req *http.Request, next HTTPDelegatedInvoker) (*http.Response, error) {
		observation := captureHTTP2E2EObservation(req)
		observed <- observation
		if observation.err != nil {
			return nil, observation.err
		}
		req = req.WithContext(context.WithValue(context.Background(), http2E2EInterceptorContextKey{}, true))
		req.Header.Set("X-Interceptor-Request", "seen")
		response, err := next.Invoke(req)
		if response != nil {
			response.Header.Set("X-Interceptor-Response", "seen")
		}
		return response, err
	}
}

func orderedHTTP2OriginHandler(observed chan<- http2E2EObservation, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		observation := captureHTTP2E2EObservation(req)
		w.Header().Set("X-Upstream-B", "second")
		w.Header().Set("X-Upstream-A", "first")
		w.Header().Set("Trailer", "X-Trailer-B, X-Trailer-A")
		if observation.err == nil {
			observation.err = http.SetResponseHeaderOrder(w, http.HeaderOrder{
				Headers:  []string{":status", "x-upstream-b", "x-upstream-a", "trailer"},
				Trailers: []string{"x-trailer-b", "x-trailer-a"},
			})
		}
		observed <- observation
		if observation.err != nil {
			http.Error(w, observation.err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = io.WriteString(w, body)
		w.Header().Set("X-Trailer-B", "trailer-second")
		w.Header().Set("X-Trailer-A", "trailer-first")
	})
}

func receiveHTTP2Observation(t *testing.T, observed <-chan http2E2EObservation) http2E2EObservation {
	t.Helper()
	select {
	case observation := <-observed:
		return observation
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HTTP/2 wire observation")
		return http2E2EObservation{}
	}
}

func assertHTTP2E2EObservation(t *testing.T, got http2E2EObservation, want http.Fingerprint, interceptorHeader bool) {
	t.Helper()
	if got.err != nil {
		t.Fatal(got.err)
	}
	if want.HeaderPriority != nil && !got.bodyIsNoBody {
		t.Fatal("HTTP/2 GET arrived without END_STREAM on its initial HEADERS frame")
	}
	if !reflect.DeepEqual(got.fingerprint, want) {
		t.Fatalf("HTTP/2 fingerprint = %#v; want %#v", got.fingerprint, want)
	}
	wantFields := append([]string(nil), want.PseudoHeaderOrder...)
	wantFields = append(wantFields, "x-zeta", "x-alpha", "user-agent")
	if interceptorHeader {
		wantFields = append(wantFields, "x-interceptor-request")
	}
	if !slices.Equal(got.fields, wantFields) {
		t.Fatalf("HTTP/2 request fields = %v; want %v", got.fields, wantFields)
	}
	wantInterceptorHeader := ""
	if interceptorHeader {
		wantInterceptorHeader = "seen"
	}
	if got.interceptorHeader != wantInterceptorHeader {
		t.Fatalf("interceptor request header = %q; want %q", got.interceptorHeader, wantInterceptorHeader)
	}
}

func assertOrderedHTTP2Response(t *testing.T, response *http.Response, wantBody string) {
	t.Helper()
	if response == nil {
		t.Fatal("nil HTTP/2 response")
	}
	defer response.Body.Close()
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusOK {
		t.Fatalf("response = %s %s; want HTTP/2 200", response.Proto, response.Status)
	}
	initialFields := http2ResponseFieldNames(response, http.HeaderBlockInitial)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != wantBody {
		t.Fatalf("response body = %q; want %q", body, wantBody)
	}
	if got := response.Header.Get("X-Interceptor-Response"); got != "seen" {
		t.Fatalf("interceptor response header = %q; want seen", got)
	}
	assertFieldPrefix(t, initialFields, []string{":status", "x-upstream-b", "x-upstream-a"})
	trailerFields := http2ResponseFieldNames(response, http.HeaderBlockTrailer)
	if want := []string{"x-trailer-b", "x-trailer-a"}; !slices.Equal(trailerFields, want) {
		t.Fatalf("response trailer fields = %v; want %v", trailerFields, want)
	}
	if got := response.Trailer.Get("X-Trailer-B"); got != "trailer-second" {
		t.Fatalf("X-Trailer-B = %q; want trailer-second", got)
	}
	if got := response.Trailer.Get("X-Trailer-A"); got != "trailer-first" {
		t.Fatalf("X-Trailer-A = %q; want trailer-first", got)
	}
}

func assertMirroredClientHello(t *testing.T, downstream *writeCaptureConn, upstreamRaw []byte) {
	t.Helper()
	downstreamRaw, err := downstream.RawClientHello()
	if err != nil {
		t.Fatal(err)
	}
	downstreamSpec := fingerprintRawClientHello(t, downstreamRaw)
	upstreamSpec := fingerprintRawClientHello(t, upstreamRaw)
	if !reflect.DeepEqual(upstreamSpec.CipherSuites, downstreamSpec.CipherSuites) {
		t.Fatalf("upstream cipher suites = %v; want %v", upstreamSpec.CipherSuites, downstreamSpec.CipherSuites)
	}
	gotExtensions := clientHelloExtensionIDsFromRaw(t, upstreamRaw)
	wantExtensions := clientHelloExtensionIDsFromRaw(t, downstreamRaw)
	if !reflect.DeepEqual(gotExtensions, wantExtensions) {
		t.Fatalf("upstream extension IDs = %v; want %v", gotExtensions, wantExtensions)
	}
}

func receiveString(t *testing.T, values <-chan string) string {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for string observation")
		return ""
	}
}

func assertNoHTTP2E2EError(t *testing.T, errCh <-chan error) {
	t.Helper()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("unexpected HTTP/2 E2E proxy error: %v", err)
		}
	default:
	}
}
