package mitmproxy

import (
	"net/http"
	"net/textproto"
	"strings"

	"golang.org/x/net/http/httpguts"
)

const (
	HttpHeaderContentType            = "Content-Type"
	HttpHeaderConnection             = "Connection"
	HttpHeaderKeepAlive              = "Keep-Alive"
	HttpHeaderProxyAuthenticate      = "Proxy-Authenticate"
	HttpHeaderProxyAuthorization     = "Proxy-Authorization"
	HttpHeaderProxyConnection        = "Proxy-Connection"
	HttpHeaderProxyAgent             = "Proxy-Agent"
	HttpHeaderTe                     = "Te"
	HttpHeaderTrailer                = "Trailer"
	HttpHeaderTransferEncoding       = "Transfer-Encoding"
	HttpHeaderUpgrade                = "Upgrade"
	HttpHeaderSecWebsocketKey        = "Sec-Websocket-Key"
	HttpHeaderSecWebsocketVersion    = "Sec-Websocket-Version"
	HttpHeaderSecWebsocketExtensions = "Sec-Websocket-Extensions"
	HttpHeaderSecWebsocketProtocol   = "Sec-Websocket-Protocol"
	HttpHeaderSecWebsocketAccept     = "Sec-Websocket-Accept"
	HttpHeaderAcceptEncoding         = "Accept-Encoding"
	HttpHeaderContentEncoding        = "Content-Encoding"
	HttpHeaderContentLength          = "Content-Length"
	HttpHeaderHttp2Settings          = "HTTP2-Settings"
)

var (
	HttpResponseConnectionEstablished = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
)

var (
	// Hop-by-hop headers. These are removed when sent to the backend.
	// http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html
	hopByHopHeaders = []string{
		HttpHeaderConnection,
		HttpHeaderKeepAlive,
		HttpHeaderProxyAuthenticate,
		HttpHeaderProxyAuthorization,
		HttpHeaderTe,
		HttpHeaderTrailer,
		HttpHeaderTransferEncoding,
		HttpHeaderUpgrade,
		HttpHeaderProxyConnection,
	}
)

func removeProxyHeaders(header http.Header) {
	header.Del(HttpHeaderProxyAuthenticate)
	header.Del(HttpHeaderProxyAuthorization)
	header.Del(HttpHeaderProxyConnection)
	header.Del(HttpHeaderProxyAgent)
}

func removeHopByHopRequestHeaders(header http.Header) {
	preserveTrailers := httpguts.HeaderValuesContainsToken(header.Values(HttpHeaderTe), "trailers")
	removeHopByHopHeaders(header)
	if preserveTrailers {
		header.Set(HttpHeaderTe, "trailers")
	}
}

func removeHopByHopHeaders(header http.Header) {
	for _, value := range header.Values(HttpHeaderConnection) {
		for _, token := range strings.Split(value, ",") {
			if token = textproto.TrimString(token); token != "" {
				header.Del(token)
			}
		}
	}
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
	header.Del(HttpHeaderProxyAgent)
}

func sanitizeWebsocketUpgradeHeaders(header http.Header) {
	for _, value := range header.Values(HttpHeaderConnection) {
		for _, token := range strings.Split(value, ",") {
			token = textproto.TrimString(token)
			if token != "" && !isWebsocketHandshakeHeader(token) {
				header.Del(token)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		if name != HttpHeaderConnection && name != HttpHeaderUpgrade {
			header.Del(name)
		}
	}
	header.Del(HttpHeaderProxyAgent)
}

func isWebsocketHandshakeHeader(name string) bool {
	name = textproto.CanonicalMIMEHeaderKey(name)
	return name == HttpHeaderConnection ||
		name == HttpHeaderUpgrade ||
		strings.HasPrefix(name, "Sec-Websocket-")
}

func isWSUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Upgrade")], "websocket") &&
		httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Connection")], "Upgrade")
}
