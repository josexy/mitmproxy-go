package mitmproxy

import (
	"net/http"
	"testing"
)

func TestRemoveHopByHopRequestHeaders(t *testing.T) {
	header := http.Header{
		"Connection":          {"keep-alive, X-Remove"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authorization": {"secret"},
		"Te":                  {"gzip, trailers"},
		"Trailer":             {"X-Trailer"},
		"X-Remove":            {"value"},
		"X-Keep":              {"value"},
	}

	removeHopByHopRequestHeaders(header)

	for _, key := range []string{"Connection", "Keep-Alive", "Proxy-Authorization", "Trailer", "X-Remove"} {
		if got := header.Get(key); got != "" {
			t.Fatalf("%s was not removed: %q", key, got)
		}
	}
	if got := header.Get("Te"); got != "trailers" {
		t.Fatalf("Te = %q; want trailers", got)
	}
	if got := header.Get("X-Keep"); got != "value" {
		t.Fatalf("X-Keep = %q; want value", got)
	}
}

func TestRemoveHopByHopHeadersRemovesTE(t *testing.T) {
	header := http.Header{"Te": {"trailers"}, "X-Keep": {"value"}}
	removeHopByHopHeaders(header)
	if got := header.Get("Te"); got != "" {
		t.Fatalf("Te was not removed: %q", got)
	}
}

func TestSanitizeWebsocketUpgradeHeaders(t *testing.T) {
	header := http.Header{
		HttpHeaderConnection:             {"keep-alive, Upgrade, X-Hop, Sec-Websocket-Extensions"},
		HttpHeaderUpgrade:                {"websocket"},
		HttpHeaderKeepAlive:              {"timeout=5"},
		HttpHeaderTe:                     {"trailers"},
		HttpHeaderProxyAgent:             {"proxy"},
		"X-Hop":                          {"secret"},
		HttpHeaderSecWebsocketKey:        {"key"},
		HttpHeaderSecWebsocketVersion:    {"13"},
		HttpHeaderSecWebsocketExtensions: {"permessage-deflate"},
		HttpHeaderSecWebsocketProtocol:   {"chat, superchat"},
		HttpHeaderSecWebsocketAccept:     {"accept"},
	}

	sanitizeWebsocketUpgradeHeaders(header)

	if got := header.Get(HttpHeaderConnection); got != "keep-alive, Upgrade, X-Hop, Sec-Websocket-Extensions" {
		t.Fatalf("Connection was changed: %q", got)
	}
	if got := header.Get(HttpHeaderUpgrade); got != "websocket" {
		t.Fatalf("Upgrade = %q; want websocket", got)
	}
	websocketHeaders := map[string]string{
		HttpHeaderSecWebsocketKey:        "key",
		HttpHeaderSecWebsocketVersion:    "13",
		HttpHeaderSecWebsocketExtensions: "permessage-deflate",
		HttpHeaderSecWebsocketProtocol:   "chat, superchat",
		HttpHeaderSecWebsocketAccept:     "accept",
	}
	for name, want := range websocketHeaders {
		if got := header.Get(name); got != want {
			t.Fatalf("%s = %q; want %q", name, got, want)
		}
	}
	for _, name := range []string{HttpHeaderKeepAlive, HttpHeaderTe, HttpHeaderProxyAgent, "X-Hop"} {
		if value := header.Get(name); value != "" {
			t.Fatalf("%s was not removed: %q", name, value)
		}
	}
}
