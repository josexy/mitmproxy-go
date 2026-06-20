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
	HttpResponseConnectionEstablished = []byte("HTTP/1.1 200 Connection Established\r\n\r\n")
)

func removeProxyHeaders(header http.Header) {
	header.Del(HttpHeaderProxyAuthenticate)
	header.Del(HttpHeaderProxyAuthorization)
	header.Del(HttpHeaderProxyConnection)
	header.Del(HttpHeaderProxyAgent)
}

func isWSUpgrade(h http.Header) bool {
	return httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Upgrade")], "websocket") &&
		httpguts.HeaderValuesContainsToken(h[textproto.CanonicalMIMEHeaderKey("Connection")], "Upgrade")
}
