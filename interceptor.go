package mitmproxy

import (
	"context"
	"errors"
	"net/http"

	"github.com/josexy/mitmproxy-go/buf"
)

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

// RawTCPTunnelEventType identifies a lifecycle event for a classified raw TCP tunnel.
type RawTCPTunnelEventType byte

const (
	// RawTCPTunnelStarted is emitted immediately before bidirectional relay begins.
	RawTCPTunnelStarted RawTCPTunnelEventType = iota
	// RawTCPTunnelEnded is emitted after bidirectional relay returns.
	RawTCPTunnelEnded
)

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

// RawTCPTunnelEvent describes one lifecycle transition for a classified raw TCP tunnel.
// It contains metadata only and never exposes the relayed connection or payload.
// TunnelID is unique within one proxy handler lifetime, but its numeric value does not
// define callback or relay ordering. Error is always nil for RawTCPTunnelStarted. For
// RawTCPTunnelEnded, Error is the passthrough relay return value: the copy result from
// the first direction to finish, which may be nil.
type RawTCPTunnelEvent struct {
	TunnelID uint64                // Identifier unique within one proxy handler lifetime.
	Type     RawTCPTunnelEventType // Started or Ended.
	Source   RawTCPTunnelSource    // Downstream tunnel entry point.
	Hostport string                // Requested target in host:port form.
	TLS      bool                  // Whether this is a decrypted raw stream inside a MITM TLS tunnel.
	Error    error                 // Passthrough relay return value for Ended; nil for Started.
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
	// RawTCPInterceptor observes classified raw TCP tunnel lifecycle events.
	// For each tunnel, RawTCPTunnelStarted is called synchronously before relay and
	// RawTCPTunnelEnded is called synchronously after relay. Callbacks for that tunnel
	// are ordered, while callbacks for different tunnels may run concurrently. A
	// callback blocks its caller: Started delays relay and Ended delays handler return.
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
