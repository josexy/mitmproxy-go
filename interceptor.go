package mitmproxy

import (
	"context"
	"errors"
	"time"

	"github.com/josexy/xhttp"

	"github.com/josexy/mitmproxy-go/buf"
)

type websocketHandshakeTimingContextKey struct{}

// WebsocketHandshakeTiming records the upstream WebSocket opening handshake.
// RequestStartedAt is captured immediately before the request is sent,
// RequestEndedAt after the request has been written, ResponseStartedAt when the
// first response byte arrives, and ResponseEndedAt after the response headers
// have been read.
type WebsocketHandshakeTiming struct {
	RequestStartedAt  time.Time
	RequestEndedAt    time.Time
	ResponseStartedAt time.Time
	ResponseEndedAt   time.Time
}

// WebsocketHandshakeTimingFromContext returns the upstream opening-handshake
// timing attached to a WebsocketInterceptor context. A successful WebSocket
// upgrade supplies all four timestamps.
func WebsocketHandshakeTimingFromContext(ctx context.Context) (WebsocketHandshakeTiming, bool) {
	if ctx == nil {
		return WebsocketHandshakeTiming{}, false
	}
	timing, ok := ctx.Value(websocketHandshakeTimingContextKey{}).(WebsocketHandshakeTiming)
	return timing, ok
}

var (
	ErrWebsocketFrameReleased   = errors.New("websocket frame was already invoked or released")
	ErrWebsocketMessageTooLarge = errors.New("websocket message exceeds configured limit")
)

// WSDirection indicates the direction of a WebSocket message
type WSDirection byte

const (
	// Send indicates a message sent from client to server
	Send WSDirection = iota
	// Receive indicates a message received from server to client
	Receive
)

func (d WSDirection) String() string {
	switch d {
	case Send:
		return "Send"
	case Receive:
		return "Receive"
	default:
		return "Unknown"
	}
}

// RawTCPTunnelSource identifies how the downstream tunnel entered the proxy.
type RawTCPTunnelSource byte

const (
	// RawTCPTunnelSourceDirect identifies a low-level or transparent Serve connection.
	RawTCPTunnelSourceDirect RawTCPTunnelSource = iota
	// RawTCPTunnelSourceHTTPConnect identifies an HTTP CONNECT tunnel.
	RawTCPTunnelSourceHTTPConnect
	// RawTCPTunnelSourceSOCKS5 identifies a SOCKS5 CONNECT tunnel.
	RawTCPTunnelSourceSOCKS5
)

// RawTCPTunnelEvent describes a classified raw TCP tunnel immediately before relay.
// Request is a bodyless snapshot of the outer CONNECT request when Source is
// RawTCPTunnelSourceHTTPConnect and the tunnel entered through ServeHTTP; otherwise
// Request is nil. The event never exposes a relayed connection or payload.
type RawTCPTunnelEvent struct {
	Source   RawTCPTunnelSource // Downstream tunnel entry point.
	Hostport string             // Requested target in host:port form.
	TLS      bool               // Whether this is a decrypted raw stream inside a MITM TLS tunnel.
	Request  *http.Request      // Bodyless outer CONNECT snapshot for ServeHTTP tunnels; otherwise nil.
}

type WsFrame interface {
	Direction() WSDirection
	MessageType() int
	DataBuffer() *buf.Buffer

	// Forward the websocket message and release the data buffer
	Invoke() error
	// MUST be called to release the data buffer
	Release()
}

type (
	HTTPDelegatedInvoker interface {
		Invoke(request *http.Request) (*http.Response, error)
	}

	WebsocketDelegatedInvoker interface {
		Invoke(msgType int, dataPtr *buf.Buffer) error
	}
	WebsocketFramesWatcher interface {
		Receive() <-chan WsFrame
	}
)

type (
	HTTPDelegatedInvokerFunc      func(*http.Request) (*http.Response, error)
	WebsocketDelegatedInvokerFunc func(int, *buf.Buffer) error

	HTTPInterceptor      func(context.Context, *http.Request, HTTPDelegatedInvoker) (*http.Response, error)
	WebsocketInterceptor func(context.Context, *http.Request, *http.Response, WebsocketFramesWatcher)
	// RawTCPInterceptor observes classified raw TCP tunnels. It is called synchronously
	// once per tunnel immediately before relay, so a slow callback delays relay.
	// Callbacks for different tunnels may run concurrently.
	//
	// RawTCPInterceptor is observation-only. It receives no relayed connection or
	// payload and cannot allow, reject, or modify relay.
	RawTCPInterceptor func(context.Context, RawTCPTunnelEvent)
)

func (f HTTPDelegatedInvokerFunc) Invoke(r *http.Request) (*http.Response, error) { return f(r) }
func (f WebsocketDelegatedInvokerFunc) Invoke(t int, data *buf.Buffer) error      { return f(t, data) }

func wrapperInvoker(fn func(messageType int, data []byte) error) WebsocketDelegatedInvokerFunc {
	return func(i int, b *buf.Buffer) error {
		return fn(i, b.Bytes())
	}
}

func chainHTTPInterceptors(interceptors []HTTPInterceptor) HTTPInterceptor {
	return func(ctx context.Context, req *http.Request, hi HTTPDelegatedInvoker) (*http.Response, error) {
		return interceptors[0](ctx, req, getChainHTTPInterceptor(interceptors, 0, ctx, hi))
	}
}

func getChainHTTPInterceptor(interceptors []HTTPInterceptor, curr int, ctx context.Context, finalInvoker HTTPDelegatedInvoker) HTTPDelegatedInvoker {
	if curr == len(interceptors)-1 {
		return finalInvoker
	}
	return HTTPDelegatedInvokerFunc(func(r *http.Request) (*http.Response, error) {
		return interceptors[curr+1](ctx, r, getChainHTTPInterceptor(interceptors, curr+1, ctx, finalInvoker))
	})
}
