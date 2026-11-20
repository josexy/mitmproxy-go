package mitmproxy

import (
	"crypto/tls"
	"net/url"
	"sync"
	"testing"

	http "github.com/josexy/xhttp"
)

func TestRequestMatchesTarget(t *testing.T) {
	for _, test := range []struct {
		name, target, authority, scheme, serverName string
		canRetarget, want                           bool
	}{
		{"TLS domain", "192.0.2.1:443", "example.test", "https", "example.test", false, true},
		{"case and root dot", "192.0.2.1:443", "EXAMPLE.test.", "https", "example.test", false, true},
		{"IPv6 tunnel", "[2001:db8::1]:443", "example.test", "https", "example.test", false, true},
		{"explicit port", "192.0.2.1:8443", "example.test:8443", "https", "example.test", false, true},
		{"implicit wrong port", "192.0.2.1:8443", "example.test", "https", "example.test", false, false},
		{"explicit wrong port", "192.0.2.1:443", "example.test:80", "https", "example.test", false, false},
		{"WSS default port", "192.0.2.1:443", "example.test", "wss", "example.test", false, true},
		{"HTTP default port", "192.0.2.1:80", "example.test", "http", "", false, true},
		{"TLS without SNI", "192.0.2.1:443", "example.test", "https", "", false, true},
		{"wrong SNI", "192.0.2.1:443", "other.test", "https", "example.test", false, false},
		{"domain tunnel", "example.test:443", "other.test", "https", "other.test", false, false},
		{"original IP", "192.0.2.1:443", "192.0.2.1", "https", "example.test", false, true},
		{"different IP", "192.0.2.1:443", "192.0.2.2", "https", "example.test", false, false},
		{"different IP without SNI", "192.0.2.1:443", "192.0.2.2", "https", "", false, false},
		{"IPv6 authority", "192.0.2.1:443", "[2001:db8::2]", "https", "", false, false},
		{"plain proxy retarget", "192.0.2.1:80", "example.test", "http", "", true, false},
		{"empty authority", "192.0.2.1:443", "", "https", "", false, false},
		{"userinfo", "192.0.2.1:443", "user@example.test", "https", "", false, false},
		{"invalid domain", "192.0.2.1:443", "example..test", "https", "", false, false},
		{"bracketed domain", "192.0.2.1:443", "[example.test]", "https", "", false, false},
		{"bracketed domain with port", "192.0.2.1:443", "[example.test]:443", "https", "", false, false},
		{"trailing space", "192.0.2.1:443", "example.test ", "https", "", false, false},
		{"empty port", "192.0.2.1:443", "example.test:", "https", "", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			conn := &biConnContext{clientHello: &capturedClientHello{info: &tls.ClientHelloInfo{ServerName: test.serverName}}}
			req := &http.Request{Host: test.authority, URL: &url.URL{Scheme: test.scheme}}
			if got := conn.requestMatchesTarget(req, test.target, test.canRetarget); got != test.want {
				t.Fatalf("requestMatchesTarget = %t, want %t", got, test.want)
			}
		})
	}
}

func TestIPTunnelAuthorityBinding(t *testing.T) {
	conn := &biConnContext{}
	if conn.requestMatchesTarget(nil, "192.0.2.1:443", false) {
		t.Fatal("nil request matched")
	}
	// A rejected request must not claim the authority for later valid requests.
	req := &http.Request{Host: "wrong-port.test:8443", TLS: &tls.ConnectionState{}}
	if conn.requestMatchesTarget(req, "192.0.2.1:443", false) {
		t.Fatal("wrong port matched")
	}
	req = &http.Request{URL: &url.URL{Host: "first.test"}, TLS: &tls.ConnectionState{}}
	if !conn.requestMatchesTarget(req, "192.0.2.1:443", false) {
		t.Fatal("URL authority with TLS default port did not match")
	}
	for _, test := range []struct {
		host string
		want bool
	}{{"FIRST.test.", true}, {"other.test", false}, {"192.0.2.1", true}, {"first.test", true}} {
		req.Host = test.host
		if got := conn.requestMatchesTarget(req, "192.0.2.1:443", false); got != test.want {
			t.Errorf("authority %q matched = %t, want %t", test.host, got, test.want)
		}
	}
}

func TestIPTunnelAuthorityConcurrentBinding(t *testing.T) {
	conn := &biConnContext{}
	start := make(chan struct{})
	results := make(chan string, 32)
	var workers sync.WaitGroup
	for i := range 32 {
		workers.Go(func() {
			<-start
			host := "first.test"
			if i%2 != 0 {
				host = "second.test"
			}
			req := &http.Request{Host: host, URL: &url.URL{Scheme: "http"}}
			if conn.requestMatchesTarget(req, "192.0.2.1:80", false) {
				results <- host
			}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	var accepted string
	count := 0
	for host := range results {
		if accepted != "" && accepted != host {
			t.Fatalf("concurrent streams accepted both %q and %q", accepted, host)
		}
		accepted = host
		count++
	}
	if count != 16 {
		t.Fatalf("accepted %d streams, want all 16 streams for one authority", count)
	}
}
