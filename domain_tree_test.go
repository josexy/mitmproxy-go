package mitmproxy

import (
	"errors"
	"net"
	"strings"
	"testing"
)

func TestDomainTreeMatch(t *testing.T) {
	includeHosts := []string{
		"*.example.com",
		"google.com",
		"*.internal.net",
		"www.*.baidu.com",
	}
	matcher := newTrieNode()
	for _, pattern := range includeHosts {
		matcher.insert(pattern)
	}
	testCases := []struct {
		host    string
		matched bool
	}{
		{"www.example.com", true},
		{"api.example.com", true},
		{"example.com", false},
		{"sub.test.example.com", true},
		{"google.com", true},
		{"www.google.com", false},
		{"service.internal.net", true},
		{"db.secret.internal.net", true},
		{"localhost", false},
		{"baidu.com", false},
		{"www.baidu.com", false},
		{"www.api.baidu.db.com", false},
		{"www.api.baidu.com", true},
		{"WWW.EXAMPLE.COM.", true},
	}

	for _, tc := range testCases {
		if tc.matched != matcher.match(tc.host) {
			t.Errorf("host: %s not matched", tc.host)
		}
	}
}

func TestDomainTreeWildcardMatchesOneOrMoreLabels(t *testing.T) {
	tests := []struct {
		pattern string
		host    string
		matched bool
	}{
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "a.b.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "notexample.com", false},
		{"api.*.example.com", "api.staging.example.com", true},
		{"api.*.example.com", "api.eu.staging.example.com", true},
		{"api.*.example.com", "api.example.com", false},
		{"api.*.example.com", "www.eu.staging.example.com", false},
		{"*.*.example.com", "a.b.example.com", true},
		{"*.*.example.com", "a.b.c.example.com", true},
		{"*.*.example.com", "a.example.com", false},
		{"*", "localhost", true},
		{"*", "www.example.com", true},
	}
	for _, tc := range tests {
		t.Run(tc.pattern+"/"+tc.host, func(t *testing.T) {
			matcher := newTrieNode()
			if err := matcher.insert(tc.pattern); err != nil {
				t.Fatal(err)
			}
			if got := matcher.match(tc.host); got != tc.matched {
				t.Fatalf("match(%q) = %v; want %v", tc.host, got, tc.matched)
			}
		})
	}
}

func TestDomainTreeWildcardBacktrackingDoesNotMixPatterns(t *testing.T) {
	matcher := newTrieNode()
	for _, pattern := range []string{"api.*.example.com", "fixed.example.com"} {
		if err := matcher.insert(pattern); err != nil {
			t.Fatal(err)
		}
	}

	if matcher.match("other.fixed.example.com") {
		t.Fatal("wildcard backtracking mixed two independent patterns")
	}
}

func TestDomainTreeRejectsMalformedDomains(t *testing.T) {
	matcher := newTrieNode()
	matcher.insert("example.com")
	matcher.insert("*.internal.example")

	for _, host := range []string{
		".example.com",
		"..example.com",
		"example..com",
		"example.com..",
		"..internal.example",
	} {
		if matcher.match(host) {
			t.Errorf("malformed host %q unexpectedly matched", host)
		}
	}
}

func TestDomainTreeCanonicalizesIDNAndIPAddresses(t *testing.T) {
	matcher := newTrieNode()
	matcher.insert("b\u00fccher.example")
	matcher.insert("[2001:0DB8:0:0:0:0:0:1]")

	for _, host := range []string{
		"B\u00dcCHER.EXAMPLE.",
		"xn--bcher-kva.example",
		"2001:db8::1",
		"[2001:db8::1]",
	} {
		if !matcher.match(host) {
			t.Errorf("canonical host %q did not match", host)
		}
	}
}

func TestDomainTreeRejectsInvalidPatterns(t *testing.T) {
	for _, pattern := range []string{
		"",
		"   ",
		".",
		".example.com",
		"example..com",
		"example.com..",
		"foo*.example.com",
		"**.example.com",
		"example.com:443",
		"[example.com]",
		"-api.example.com",
		"api-.example.com",
		"api_server.example.com",
		strings.Repeat("a", 64) + ".example.com",
	} {
		t.Run(pattern, func(t *testing.T) {
			matcher := newTrieNode()
			if err := matcher.insert(pattern); !errors.Is(err, ErrInvalidHostFilter) {
				t.Fatalf("insert(%q) error = %v; want ErrInvalidHostFilter", pattern, err)
			}
		})
	}
}

func TestDomainTreeAcceptsValidPatterns(t *testing.T) {
	for _, pattern := range []string{
		"example.com",
		"example.com.",
		"*.example.com",
		"api.*.example.com",
		"*",
		"b\u00fccher.example",
		"*.b\u00fccher.example",
		"127.0.0.1",
		"::1",
		"[2001:db8::1]",
	} {
		t.Run(pattern, func(t *testing.T) {
			matcher := newTrieNode()
			if err := matcher.insert(pattern); err != nil {
				t.Fatalf("insert(%q) unexpected error: %v", pattern, err)
			}
		})
	}
}

func TestBuildRuntimeConfigRejectsInvalidHostFilters(t *testing.T) {
	for _, option := range []Option{
		WithIncludeHosts(" "),
		WithExcludeHosts("foo*.example.com"),
	} {
		state := newRuntimeConfigStateFromOptions(newOptions(option))
		if _, err := buildRuntimeConfig(state); !errors.Is(err, ErrInvalidHostFilter) {
			t.Fatalf("buildRuntimeConfig() error = %v; want ErrInvalidHostFilter", err)
		}
	}
}

func TestSetHostFiltersRejectsInvalidUpdate(t *testing.T) {
	state := newRuntimeConfigStateFromOptions(newOptions(WithIncludeHosts("example.com")))
	cfg, err := buildRuntimeConfig(state)
	if err != nil {
		t.Fatal(err)
	}
	handler := &mitmProxyHandler{runtimeState: cfg.state}
	handler.config.Store(cfg)

	if err := handler.SetHostFilters([]string{"foo*.example.com"}, nil); !errors.Is(err, ErrInvalidHostFilter) {
		t.Fatalf("SetHostFilters() error = %v; want ErrInvalidHostFilter", err)
	}
	current := handler.config.Load()
	if !current.domainMatcher.include.match("example.com") {
		t.Fatal("invalid update replaced the previous host filter")
	}
}

func TestShouldPassthroughRequestUsesCompiledHostFilters(t *testing.T) {
	state := newRuntimeConfigStateFromOptions(newOptions(
		WithIncludeHosts("*.example.com", "b\u00fccher.example", "[::1]"),
		WithExcludeHosts("private.example.com"),
	))
	cfg, err := buildRuntimeConfig(state)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		host        string
		passthrough bool
		reason      string
	}{
		{"api.example.com", false, "intercept"},
		{"private.example.com", true, "exclude_host"},
		{"v1.api.example.com", false, "intercept"},
		{"example.com", true, "not_in_include_hosts"},
		{"xn--bcher-kva.example", false, "intercept"},
		{"::1", false, "intercept"},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			passthrough, reason := shouldPassthroughRequest(cfg, net.JoinHostPort(tc.host, "443"))
			if passthrough != tc.passthrough || reason != tc.reason {
				t.Fatalf("decision = (%v, %q); want (%v, %q)", passthrough, reason, tc.passthrough, tc.reason)
			}
		})
	}
}

func BenchmarkDomainTreeMatch(b *testing.B) {
	matcher := newTrieNode()
	for _, pattern := range []string{
		"*.example.com",
		"google.com",
		"*.internal.net",
		"www.*.baidu.com",
	} {
		matcher.insert(pattern)
	}

	b.ReportAllocs()
	for b.Loop() {
		if !matcher.match("www.api.baidu.com") {
			b.Fatal("expected host to match")
		}
	}
}
