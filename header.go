package mitmproxy

import (
	"net/http"
	"net/textproto"

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
	HttpHeaderTrailers               = "Trailers"
	HttpHeaderTransferEncoding       = "Transfer-Encoding"
	HttpHeaderUpgrade                = "Upgrade"
	HttpHeaderSecWebsocketKey        = "Sec-Websocket-Key"
	HttpHeaderSecWebsocketVersion    = "Sec-Websocket-Version"
	HttpHeaderSecWebsocketExtensions = "Sec-Websocket-Extensions"
	HttpHeaderAcceptEncoding         = "Accept-Encoding"
	HttpHeaderContentEncoding        = "Content-Encoding"
	HttpHeaderContentLength          = "Content-Length"
	HttpHeaderHttp2Settings          = "HTTP2-Settings"
)

var (
	HttpResponseConnectionEstablished    = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
	H2CUpgradeResponseSwitchingProtocols = []byte("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n")
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
		HttpHeaderTrailers,
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
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

func removeWebsocketRequestHeaders(header http.Header) {
	header.Del(HttpHeaderUpgrade)
	header.Del(HttpHeaderConnection)
	header.Del(HttpHeaderSecWebsocketKey)
	header.Del(HttpHeaderSecWebsocketVersion)
	header.Del(HttpHeaderSecWebsocketExtensions)
}

func isWSUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Upgrade")], "websocket") &&
		httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Connection")], "Upgrade")
}
