package mitmproxy

import (
	"context"
	"net/http"

	"github.com/josexy/mitmproxy-go/buf"
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
