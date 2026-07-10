package mitmproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

const dialTimeout = 15 * time.Second

func init() {
	newHTTPProxyDialer := func(proxyURL *url.URL, forwardDialer proxy.Dialer) (proxy.Dialer, error) {
		dialer := &httpProxyDialer{proxyURL: proxyURL, forwardDial: forwardDialer.Dial}
		if contextDialer, ok := forwardDialer.(proxy.ContextDialer); ok {
			dialer.forwardDialContext = contextDialer.DialContext
		}
		return dialer, nil
	}
	proxy.RegisterDialerType("http", newHTTPProxyDialer)
	proxy.RegisterDialerType("https", newHTTPProxyDialer)
}

type httpProxyDialer struct {
	proxyURL           *url.URL
	forwardDial        func(network, addr string) (net.Conn, error)
	forwardDialContext func(context.Context, string, string) (net.Conn, error)
	tlsConfig          *tls.Config
	maxHeaderBytes     int
}

func hostPortNoPort(u *url.URL) (hostPort, hostNoPort string) {
	hostPort = u.Host
	hostNoPort = u.Host
	if i := strings.LastIndex(u.Host, ":"); i > strings.LastIndex(u.Host, "]") {
		hostNoPort = hostNoPort[:i]
	} else {
		switch u.Scheme {
		case "wss":
			hostPort += ":443"
		case "https":
			hostPort += ":443"
		default:
			hostPort += ":80"
		}
	}
	return hostPort, hostNoPort
}

func (hpd *httpProxyDialer) Dial(network string, addr string) (net.Conn, error) {
	return hpd.DialContext(context.Background(), network, addr)
}

func (hpd *httpProxyDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	hostPort, _ := hostPortNoPort(hpd.proxyURL)
	var conn net.Conn
	var err error
	if hpd.forwardDialContext != nil {
		conn, err = hpd.forwardDialContext(ctx, network, hostPort)
	} else {
		conn, err = hpd.forwardDial(network, hostPort)
	}
	if err != nil {
		return nil, err
	}
	if hpd.proxyURL.Scheme == "https" {
		tlsConfig := hpd.tlsConfig
		if tlsConfig == nil {
			tlsConfig = &tls.Config{}
		} else {
			tlsConfig = tlsConfig.Clone()
		}
		if tlsConfig.ServerName == "" {
			tlsConfig.ServerName = hpd.proxyURL.Hostname()
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("TLS handshake with HTTPS proxy: %w", err)
		}
		conn = tlsConn
	}
	clearDeadline := setDeadlineFromContext(ctx, conn)
	defer clearDeadline()

	var connectHeader http.Header
	if user := hpd.proxyURL.User; user != nil {
		proxyUser := user.Username()
		proxyPassword, _ := user.Password()
		credential := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPassword))
		connectHeader = make(http.Header)
		connectHeader.Set("Proxy-Authorization", "Basic "+credential)
	}

	connectReq := &http.Request{
		Method: http.MethodConnect, // We use CONNECT method to establish tunnel whatever the request protocol
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: connectHeader,
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, contextAwareError(ctx, err)
	}

	// Preserve bytes buffered after the CONNECT response for server-first protocols.
	maxHeaderBytes := hpd.maxHeaderBytes
	if maxHeaderBytes <= 0 {
		maxHeaderBytes = http.DefaultMaxHeaderBytes
	}
	resp, br, err := readBoundedHTTPResponse(bufio.NewReader(conn), connectReq, maxHeaderBytes)
	if err != nil {
		conn.Close()
		return nil, contextAwareError(ctx, err)
	}

	if resp.StatusCode != 200 {
		conn.Close()
		f := strings.SplitN(resp.Status, " ", 2)
		if len(f) == 2 {
			return nil, errors.New(f[1])
		}
		return nil, errors.New(resp.Status)
	}
	if err := ctx.Err(); err != nil {
		conn.Close()
		return nil, err
	}
	return &bufConnExt{Conn: conn, Reader: br}, nil
}

func contextAwareError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

func setDeadlineFromContext(ctx context.Context, conn net.Conn) func() {
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
		close(done)
	})
	var once sync.Once
	return func() {
		once.Do(func() {
			if !stop() {
				<-done
			}
			_ = conn.SetDeadline(time.Time{})
		})
	}
}

type netDialerFunc func(network, addr string) (net.Conn, error)

func (fn netDialerFunc) Dial(network, addr string) (net.Conn, error) {
	return fn(network, addr)
}

type addrConn struct {
	raddr net.Addr
	net.Conn
}

func (c *addrConn) RemoteAddr() net.Addr {
	return c.raddr
}

type proxyDialer struct {
	proxyURL  *url.URL
	dialer    *net.Dialer
	proxyFunc func(*url.URL) (*url.URL, error)
}

type dialTimestampRecorder interface {
	SetDNSLookupStartTs(time.Time)
	SetDNSLookupCompletedTs(time.Time)
	SetSocketConnectStartTs(time.Time)
	SetSocketConnectCompletedTs(time.Time)
}

func NewProxyDialer(proxyURL *url.URL, dialer *net.Dialer) *proxyDialer {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: dialTimeout}
	}
	return &proxyDialer{proxyURL: proxyURL, dialer: dialer}
}

func newConfiguredProxyDialer(proxyURL *url.URL, dialer *net.Dialer, useEnvironment bool) *proxyDialer {
	d := NewProxyDialer(proxyURL, dialer)
	if useEnvironment {
		cfg := httpproxy.FromEnvironment()
		proxyFunc := cfg.ProxyFunc()
		targetScheme := "http"
		if cfg.HTTPProxy == "" && cfg.HTTPSProxy != "" {
			targetScheme = "https"
		}
		d.proxyFunc = func(target *url.URL) (*url.URL, error) {
			targetCopy := *target
			targetCopy.Scheme = targetScheme
			return proxyFunc(&targetCopy)
		}
	}
	return d
}

func (d *proxyDialer) DialTCP(addr string) (net.Conn, error) {
	return d.Dial("tcp", addr)
}

func (d *proxyDialer) DialTCPContext(ctx context.Context, addr string) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *proxyDialer) DialTCPContextWithMetadata(ctx context.Context, addr string, md dialTimestampRecorder) (net.Conn, error) {
	return d.dialWithMetadata(ctx, "tcp", addr, md)
}

func (d *proxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *proxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

func (d *proxyDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dialWithMetadata(ctx, network, addr, nil)
}

func (d *proxyDialer) dialWithMetadata(ctx context.Context, network, addr string, md dialTimestampRecorder) (net.Conn, error) {
	proxyURL, err := d.proxyURLForAddress(addr)
	if err != nil {
		return nil, err
	}
	forward := &contextNetDialer{dialer: d.dialer, md: md}
	if proxyURL == nil {
		return forward.DialContext(ctx, network, addr)
	}
	dialCtx := ctx
	cancel := func() {}
	if d.dialer.Timeout > 0 {
		dialCtx, cancel = context.WithTimeout(ctx, d.dialer.Timeout)
	}
	defer cancel()
	resolvedAddr, err := d.resolveTCPAddr(dialCtx, network, addr, md)
	if err != nil {
		return nil, err
	}
	// The destination lookup above is the DNS phase represented by the
	// connection metadata. Do not overwrite it when resolving the proxy host.
	forward.skipDNSMetadata = true
	dialer, err := proxy.FromURL(proxyURL, forward)
	if err != nil {
		return nil, err
	}
	var conn net.Conn
	if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
		conn, err = contextDialer.DialContext(dialCtx, network, resolvedAddr.String())
	} else {
		conn, err = dialer.Dial(network, resolvedAddr.String())
	}
	if err != nil {
		return nil, err
	}
	return &addrConn{raddr: resolvedAddr, Conn: conn}, nil
}

func (d *proxyDialer) resolveTCPAddr(ctx context.Context, network, addr string, md dialTimestampRecorder) (*net.TCPAddr, error) {
	host, portString, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portString)
	if err != nil {
		lookupNetwork := network
		if lookupNetwork == "tcp4" || lookupNetwork == "tcp6" {
			lookupNetwork = "tcp"
		}
		port, err = net.LookupPort(lookupNetwork, portString)
		if err != nil {
			return nil, err
		}
	}
	if port < 0 || port > 65535 {
		return nil, net.InvalidAddrError("invalid port " + portString)
	}

	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if ip := net.ParseIP(host); ip != nil {
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}

	if md != nil {
		md.SetDNSLookupStartTs(time.Now())
		defer func() {
			md.SetDNSLookupCompletedTs(time.Now())
		}()
	}
	resolver := d.dialer.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, ip := range ips {
		if network == "tcp4" && ip.IP.To4() == nil {
			continue
		}
		if network == "tcp6" && (ip.IP.To4() != nil || ip.IP.To16() == nil) {
			continue
		}
		return &net.TCPAddr{IP: ip.IP, Port: port, Zone: ip.Zone}, nil
	}
	return nil, &net.DNSError{Name: host, Err: "no suitable address found"}
}

func (d *proxyDialer) proxyURLForAddress(addr string) (*url.URL, error) {
	if d.proxyFunc == nil {
		return d.proxyURL, nil
	}
	return d.proxyFunc(&url.URL{Scheme: "http", Host: addr})
}

type contextNetDialer struct {
	dialer          *net.Dialer
	md              dialTimestampRecorder
	skipDNSMetadata bool
}

func (d *contextNetDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *contextNetDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	recordDNS := d.md != nil && !d.skipDNSMetadata && shouldRecordDNSLookup(addr)
	if recordDNS {
		d.md.SetDNSLookupStartTs(time.Now())
	}
	dialer := *d.dialer
	originalControlContext := dialer.ControlContext
	originalControl := dialer.Control
	dialer.Control = nil
	var connectStartOnce sync.Once
	var connectStarted atomic.Bool
	dialer.ControlContext = func(ctx context.Context, network, address string, rawConn syscall.RawConn) error {
		connectStartOnce.Do(func() {
			connectStarted.Store(true)
			now := time.Now()
			if recordDNS {
				d.md.SetDNSLookupCompletedTs(now)
			}
			if d.md != nil {
				d.md.SetSocketConnectStartTs(now)
			}
		})
		if originalControlContext != nil {
			return originalControlContext(ctx, network, address, rawConn)
		}
		if originalControl != nil {
			return originalControl(network, address, rawConn)
		}
		return nil
	}
	conn, err := dialer.DialContext(ctx, network, addr)
	now := time.Now()
	if recordDNS && !connectStarted.Load() {
		d.md.SetDNSLookupCompletedTs(now)
	}
	if d.md != nil && connectStarted.Load() {
		d.md.SetSocketConnectCompletedTs(now)
	}
	return conn, err
}

func shouldRecordDNSLookup(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	return net.ParseIP(strings.Trim(host, "[]")) == nil
}

func parseProxyFrom(disabled bool, proxy string) (proxyURL *url.URL, err error) {
	if disabled {
		return nil, nil
	}
	if proxy != "" {
		if proxyURL, err = url.Parse(proxy); err != nil {
			return
		}
	}
	if proxyURL == nil {
		proxyConfig := httpproxy.FromEnvironment()
		if proxyConfig.HTTPProxy != "" {
			if proxyURL, err = url.Parse(proxyConfig.HTTPProxy); err != nil {
				return
			}
		} else if proxyConfig.HTTPSProxy != "" {
			if proxyURL, err = url.Parse(proxyConfig.HTTPSProxy); err != nil {
				return
			}
		}
	}
	if proxyURL != nil {
		switch proxyURL.Scheme {
		case "http", "https", "socks5", "socks5h":
		default:
			return nil, fmt.Errorf("unsupported proxy scheme %q", proxyURL.Scheme)
		}
		if proxyURL.Host == "" {
			return nil, errors.New("proxy URL host is empty")
		}
	}
	return
}
