package mitmproxy

import (
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
		{"sub.test.example.com", false},
		{"google.com", true},
		{"www.google.com", false},
		{"service.internal.net", true},
		{"db.secret.internal.net", false},
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
