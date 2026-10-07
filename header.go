package mitmproxy

import (
	"net/textproto"
	"strings"

	http "github.com/josexy/xhttp"
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
	preserveTrailers := false
	for name, values := range header {
		if strings.EqualFold(name, HttpHeaderTe) && httpguts.HeaderValuesContainsToken(values, "trailers") {
			preserveTrailers = true
		}
	}
	removeHopByHopHeaders(header)
	if preserveTrailers {
		header.Set(HttpHeaderTe, "trailers")
	}
}

func removeHopByHopHeaders(header http.Header) {
	blocked := make(map[string]bool, len(hopByHopHeaders)+1)
	for _, name := range hopByHopHeaders {
		blocked[strings.ToLower(name)] = true
	}
	blocked[strings.ToLower(HttpHeaderProxyAgent)] = true
	for name, values := range header {
		if !strings.EqualFold(name, HttpHeaderConnection) {
			continue
		}
		for _, value := range values {
			for token := range strings.SplitSeq(value, ",") {
				if token = textproto.TrimString(token); token != "" {
					blocked[strings.ToLower(token)] = true
				}
			}
		}
	}
	for name := range header {
		if blocked[strings.ToLower(name)] {
			delete(header, name)
		}
	}
}

func sanitizeWebsocketUpgradeHeaders(header http.Header) {
	for _, value := range header.Values(HttpHeaderConnection) {
		for token := range strings.SplitSeq(value, ",") {
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
	// The upstream WebSocket handshake uses a new connection. Recreate only
	// the connection option required by RFC 6455.
	header.Set(HttpHeaderConnection, HttpHeaderUpgrade)
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
