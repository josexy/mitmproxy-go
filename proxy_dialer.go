package mitmproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

const dialTimeout = 15 * time.Second

func init() {
	proxy.RegisterDialerType("http", func(proxyURL *url.URL, forwardDialer proxy.Dialer) (proxy.Dialer, error) {
		return &httpProxyDialer{proxyURL: proxyURL, forwardDial: forwardDialer.Dial}, nil
	})
}

type httpProxyDialer struct {
	proxyURL    *url.URL
	forwardDial func(network, addr string) (net.Conn, error)
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
	hostPort, _ := hostPortNoPort(hpd.proxyURL)
	conn, err := hpd.forwardDial(network, hostPort)
	if err != nil {
		return nil, err
	}

	connectHeader := make(http.Header)
	if user := hpd.proxyURL.User; user != nil {
		proxyUser := user.Username()
		if proxyPassword, passwordSet := user.Password(); passwordSet {
			credential := base64.StdEncoding.EncodeToString([]byte(proxyUser + ":" + proxyPassword))
			connectHeader.Set("Proxy-Authorization", "Basic "+credential)
		}
	}

	connectReq := &http.Request{
		Method: http.MethodConnect, // We use CONNECT method to establish tunnel whatever the request protocol
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: connectHeader,
	}

	if err := connectReq.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}

	// Read response. It's OK to use and discard buffered reader here becaue
	// the remote server does not speak until spoken to.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, connectReq)
	if err != nil {
		conn.Close()
		return nil, err
	}

	if resp.StatusCode != 200 {
		conn.Close()
		f := strings.SplitN(resp.Status, " ", 2)
		return nil, errors.New(f[1])
	}
	return conn, nil
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
	proxyURL *url.URL
	dialer   *net.Dialer
}

func NewProxyDialer(proxyURL *url.URL, dialer *net.Dialer) *proxyDialer {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: dialTimeout}
	}
	return &proxyDialer{proxyURL: proxyURL, dialer: dialer}
}

func (d *proxyDialer) DialTCP(addr string) (net.Conn, error) {
	return d.Dial("tcp", addr)
}

func (d *proxyDialer) DialTCPContext(ctx context.Context, addr string) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", addr)
}

func (d *proxyDialer) Dial(network, addr string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, addr)
}

func (d *proxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d.dial(ctx, network, addr)
}

func (d *proxyDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	raddr, err := net.ResolveTCPAddr(network, addr)
	if err != nil {
		return nil, err
	}
	netDial := func(network, addr string) (net.Conn, error) {
		return d.dialer.DialContext(ctx, network, addr)
	}
	if d.proxyURL == nil {
		return netDial(network, addr)
	}
	dialer, err := proxy.FromURL(d.proxyURL, netDialerFunc(netDial))
	if err != nil {
		return nil, err
	}
	netDial = dialer.Dial
	conn, err := netDial(network, addr)
	if err != nil {
		return nil, err
	}
	return &addrConn{raddr, conn}, nil
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
	return
}
