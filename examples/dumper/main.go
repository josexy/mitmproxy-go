package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/josexy/mitmproxy-go"
	"github.com/josexy/mitmproxy-go/metadata"
)

const CHUNK_SIZE = 512

const (
	CHUNK_TYPE_REQ = 1 << iota
	CHUNK_TYPE_RSP
)

type bodyDecoder struct {
	reader io.ReadCloser
	pw     *io.PipeWriter
}

func newBodyDecoder(r io.ReadCloser, encoding string, chunkType int) (io.ReadCloser, error) {
	if r == http.NoBody { // no body and no need to replace it
		return r, nil
	}
	if encoding == "" {
		return newChunkBodyReader(r, CHUNK_SIZE, chunkType), nil
	}

	pr, pw := io.Pipe()
	teeReader := io.TeeReader(r, pw)
	go func() {
		decodedReader, err := getDecodedReader(pr, encoding)
		if err != nil {
			// if the decoder creation fails, we need to read pr to avoid pw blocking
			io.Copy(io.Discard, pr)
			return
		}
		decodedReader = newChunkBodyReader(decodedReader, CHUNK_SIZE, chunkType)
		defer decodedReader.Close()
		// need to read all data to avoid pw blocking, but we don't care about the decoded data here, so just discard it
		io.Copy(io.Discard, decodedReader)
	}()
	return &bodyDecoder{
		reader: io.NopCloser(teeReader),
		pw:     pw,
	}, nil
}

func (b *bodyDecoder) Close() error {
	return b.reader.Close()
}

func (b *bodyDecoder) Read(p []byte) (n int, err error) {
	n, err = b.reader.Read(p)
	if err == io.EOF {
		// when reader is closed or reaches EOF, we should also close the pipe writer to avoid goroutine leak
		b.pw.CloseWithError(err)
	}
	return
}

type chunkBodyReader struct {
	io.ReadCloser
	N         int64
	buf       bytes.Buffer // or use buf pool?
	chunkType int
}

func newChunkBodyReader(r io.ReadCloser, chunkBodySize int64, chunkType int) io.ReadCloser {
	return &chunkBodyReader{
		N:          chunkBodySize,
		ReadCloser: r,
		chunkType:  chunkType,
	}
}

func (r *chunkBodyReader) Read(p []byte) (n int, err error) {
	if r.N <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.N {
		p = p[0:r.N]
	}
	n, err = r.ReadCloser.Read(p)
	if n > 0 {
		r.buf.Write(p[:n])
		// fmt.Printf("--> hex dump(chunk size/data size: %d/%d):\n%s\n", r.N, n, hex.Dump(p[:n]))
	}
	if err == io.EOF {
		fmt.Printf("<<-- [%d]full data dump (%d bytes):\n", r.chunkType, r.buf.Len())
	}
	return
}

func main() {
	var caCertPath string
	var caKeyPath string
	var mitmMode string
	var port int
	flag.StringVar(&caCertPath, "cacert", "", "ca cert path")
	flag.StringVar(&caKeyPath, "cakey", "", "ca key path")
	flag.StringVar(&mitmMode, "mode", "http", "http or socks5 mode")
	flag.IntVar(&port, "port", 10086, "proxy port")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	slog.SetDefault(logger)

	errHandler := func(ec mitmproxy.ErrorContext) {
		slog.Error("mitm proxy error",
			slog.String("remote_addr", ec.RemoteAddr),
			slog.String("hostport", ec.Hostport),
			slog.String("error", ec.Error.Error()),
		)
	}

	ctx, cancel := context.WithCancel(context.Background())

	handler, err := mitmproxy.NewMitmProxyHandler(
		mitmproxy.WithCACertPath(caCertPath),
		mitmproxy.WithCAKeyPath(caKeyPath),
		mitmproxy.WithHTTPInterceptor(httpInterceptor),
		mitmproxy.WithWebsocketInterceptor(websocketInterceptor),
		mitmproxy.WithErrorHandler(errHandler),
		mitmproxy.WithStreamBaseContext(ctx),
		// mitmproxy.WithClientCert("127.0.0.1", mitmproxy.ClientCert{
		// 	CertPath: "certs/client.crt",
		// 	KeyPath:  "certs/client.key",
		// }),
		// mitmproxy.WithRootCAs("certs/ca.crt"),
		// mitmproxy.WithIncludeHosts("ifconfig.co", "*.example.com", "example.com", "*.bilibili.com"),
		// mitmproxy.WithIncludeHosts("api.bilibili.com"),
		// mitmproxy.WithExcludeHosts("www.baidu.com"),
		// mitmproxy.WithProxy("http://127.0.0.1:7900"),
		// mitmproxy.WithDisableProxy(),
		// mitmproxy.WithDisableHTTP2(),
		// mitmproxy.WithSkipVerifySSLFromServer(),
		// mitmproxy.WithMaxWebsocketFramesPerForward(4096),
	)
	if err != nil {
		panic(err)
	}

	listenAddr := fmt.Sprintf("%s:%d", "127.0.0.1", port)
	var closeFn func()

	switch mitmMode {
	case "socks5":
		ln, err := net.Listen("tcp", listenAddr)
		if err != nil {
			panic(err)
		}
		closeFn = func() { ln.Close() }
		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					handler.ServeSOCKS5(ctx, conn)
				}()
			}
		}()
	default:
		server := &http.Server{
			Addr:        listenAddr,
			Handler:     handler,
			BaseContext: func(l net.Listener) context.Context { return ctx },
		}
		closeFn = func() { server.Close() }
		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				panic(err)
			}
		}()
	}
	slog.Info("server started")

	inter := make(chan os.Signal, 1)
	signal.Notify(inter, syscall.SIGINT)
	<-inter

	handler.Cleanup()
	slog.Info("exit")
	closeFn()
	cancel()
	time.Sleep(time.Millisecond * 500)
}

func httpInterceptor(ctx context.Context, req *http.Request, invoker mitmproxy.HTTPDelegatedInvoker) (*http.Response, error) {
	_md, _ := metadata.FromContext(ctx)
	md := _md.MD()
	slog.Debug("request",
		slog.Bool("stream_body", md.StreamBody),
		slog.String("local_source", md.LocalAddrInfo.SourceAddr.String()),
		slog.String("local_destination", md.LocalAddrInfo.DestinationAddr.String()),
		slog.String("remote_source", md.RemoteAddrInfo.SourceAddr.String()),
		slog.String("remote_destination", md.RemoteAddrInfo.DestinationAddr.String()),
		slog.String("hostport", md.RequestHostport),
		slog.String("host", req.Host),
		slog.String("proto", req.Proto),
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.Any("headers", map[string][]string(req.Header)),
	)

	if md.TLSState != nil {
		slog.Debug("tls state",
			slog.String("server_name", md.TLSState.ServerName),
			slog.String("alpn", strings.Join(md.TLSState.ALPN, ",")),
			slog.String("selected_ciphersuite", tls.CipherSuiteName(md.TLSState.SelectedCipherSuite)),
			slog.String("selected_version", tls.VersionName(md.TLSState.SelectedTLSVersion)),
			slog.String("selected_alpn", md.TLSState.SelectedALPN),
		)
	}
	if md.ServerCertificate != nil {
		slog.Debug("server certificate",
			slog.Int("version", md.ServerCertificate.Version),
			slog.String("not_after", md.ServerCertificate.NotAfter.String()),
			slog.String("not_before", md.ServerCertificate.NotBefore.String()),
			slog.String("subject", md.ServerCertificate.Subject.String()),
			slog.String("issuer", md.ServerCertificate.Issuer.String()),
			slog.String("serial_number", md.ServerCertificate.SerialNumberHex()),
			slog.String("signature_algorithm", md.ServerCertificate.SignatureAlgorithm.String()),
			slog.String("sha1_fingerprint", md.ServerCertificate.Sha1FingerprintHex()),
			slog.String("sha256_fingerprint", md.ServerCertificate.Sha256FingerprintHex()),
			slog.String("dns", strings.Join(md.ServerCertificate.DNSNames, ",")),
			slog.Any("ip", md.ServerCertificate.IPAddresses),
		)
	}

	req.Body, _ = newBodyDecoder(req.Body, "", CHUNK_TYPE_REQ)

	rsp, err := invoker.Invoke(req)
	if err != nil {
		return rsp, err
	}

	slog.Debug("response",
		slog.Time("local_connection_establishment", md.LocalConnectionEstablishedTs),
		slog.Time("remote_connection_establishment", md.RemoteConnectionEstablishedTs),
		slog.Time("ssl_handshake_completed", md.SSLHandshakeCompletedTs),
		slog.Time("request_processed", md.RequestProcessedTs),
		slog.String("status", rsp.Status),
		slog.String("protocol", rsp.Proto),
		slog.Any("headers", map[string][]string(rsp.Header)),
	)

	rsp.Body, err = newBodyDecoder(rsp.Body, rsp.Header.Get("Content-Encoding"), CHUNK_TYPE_RSP)

	return rsp, err
}

func websocketInterceptor(ctx context.Context, req *http.Request, rsp *http.Response, fw mitmproxy.WebsocketFramesWatcher) {
	_md, _ := metadata.FromContext(ctx)
	md := _md.MD()
	slog.Debug("request",
		slog.Bool("stream_body", md.StreamBody),
		slog.String("local_source", md.LocalAddrInfo.SourceAddr.String()),
		slog.String("local_destination", md.LocalAddrInfo.DestinationAddr.String()),
		slog.String("remote_source", md.RemoteAddrInfo.SourceAddr.String()),
		slog.String("remote_destination", md.RemoteAddrInfo.DestinationAddr.String()),
		slog.String("hostport", md.RequestHostport),
		slog.String("host", req.Host),
		slog.String("proto", req.Proto),
		slog.String("method", req.Method),
		slog.String("url", req.URL.String()),
		slog.Int("status_code", rsp.StatusCode),
		slog.Any("request_headers", map[string][]string(req.Header)),
		slog.Any("response_headers", map[string][]string(rsp.Header)),
	)

	data, _ := httputil.DumpRequest(req, false)
	fmt.Printf("%s\n", string(data))
	data, _ = httputil.DumpResponse(rsp, false)
	fmt.Printf("%s\n", string(data))

	if md.TLSState != nil {
		slog.Debug("tls state",
			slog.String("server_name", md.TLSState.ServerName),
			slog.String("alpn", strings.Join(md.TLSState.ALPN, ",")),
			slog.String("selected_ciphersuite", tls.CipherSuiteName(md.TLSState.SelectedCipherSuite)),
			slog.String("selected_version", tls.VersionName(md.TLSState.SelectedTLSVersion)),
			slog.String("selected_alpn", md.TLSState.SelectedALPN),
		)
	}
	if md.ServerCertificate != nil {
		slog.Debug("server certificate",
			slog.Int("version", md.ServerCertificate.Version),
			slog.String("not_after", md.ServerCertificate.NotAfter.String()),
			slog.String("not_before", md.ServerCertificate.NotBefore.String()),
			slog.String("subject", md.ServerCertificate.Subject.String()),
			slog.String("issuer", md.ServerCertificate.Issuer.String()),
			slog.String("serial_number", md.ServerCertificate.SerialNumberHex()),
			slog.String("signature_algorithm", md.ServerCertificate.SignatureAlgorithm.String()),
			slog.String("sha1_fingerprint", md.ServerCertificate.Sha1FingerprintHex()),
			slog.String("sha256_fingerprint", md.ServerCertificate.Sha256FingerprintHex()),
			slog.String("dns", strings.Join(md.ServerCertificate.DNSNames, ",")),
			slog.Any("ip", md.ServerCertificate.IPAddresses),
		)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case frame, ok := <-fw.Receive():
			if !ok {
				return
			}
			dir := frame.Direction()
			msgType := frame.MessageType()
			dataBuf := frame.DataBuffer()
			fmt.Printf("---> %s %d %s\n", dir, msgType, dataBuf.String())
			if err := frame.Invoke(); err != nil {
				slog.Error("frame invoke error", slog.String("error", err.Error()))
			}
			frame.Release()
		}
	}
}

func getDecodedReader(r io.Reader, encoding string) (io.ReadCloser, error) {
	switch encoding {
	case "gzip":
		return gzip.NewReader(r)
	case "deflate":
		zr, err := zlib.NewReader(r)
		if err != nil {
			return io.NopCloser(flate.NewReader(r)), nil
		}
		return zr, nil
	default: // other encodings...
		return io.NopCloser(r), nil
	}
}
