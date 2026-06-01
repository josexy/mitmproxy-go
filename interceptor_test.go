package mitmproxy

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/josexy/mitmproxy-go/buf"
)

func TestWSDirectionString(t *testing.T) {
	tests := []struct {
		dir  WSDirection
		want string
	}{
		{Send, "Send"},
		{Receive, "Receive"},
		{WSDirection(99), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.dir.String(); got != tt.want {
			t.Fatalf("%v.String() = %q; want %q", byte(tt.dir), got, tt.want)
		}
	}
}

func TestInvokerFuncs(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	wantResp := &http.Response{StatusCode: http.StatusAccepted}
	httpInvoker := HTTPDelegatedInvokerFunc(func(r *http.Request) (*http.Response, error) {
		if r != req {
			t.Fatalf("request pointer mismatch")
		}
		return wantResp, nil
	})
	if got, err := httpInvoker.Invoke(req); err != nil || got != wantResp {
		t.Fatalf("HTTP invoker = %v, %v; want response, nil", got, err)
	}

	wsErr := errors.New("ws")
	wsInvoker := WebsocketDelegatedInvokerFunc(func(msgType int, b *buf.Buffer) error {
		if msgType != 2 || string(b.Bytes()) != "payload" {
			t.Fatalf("ws args = %d, %q; want 2, payload", msgType, b.Bytes())
		}
		return wsErr
	})
	if err := wsInvoker.Invoke(2, buf.As([]byte("payload"))); !errors.Is(err, wsErr) {
		t.Fatalf("WS invoker err = %v; want %v", err, wsErr)
	}
}

func TestWrapperInvoker(t *testing.T) {
	var gotType int
	var gotData []byte
	invoker := wrapperInvoker(func(messageType int, data []byte) error {
		gotType = messageType
		gotData = append([]byte(nil), data...)
		return nil
	})

	if err := invoker.Invoke(1, buf.As([]byte("hello"))); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if gotType != 1 || string(gotData) != "hello" {
		t.Fatalf("wrapped args = %d, %q; want 1, hello", gotType, gotData)
	}
}

func TestChainHTTPInterceptorsOrder(t *testing.T) {
	var calls []string
	interceptors := []HTTPInterceptor{
		func(ctx context.Context, req *http.Request, invoker HTTPDelegatedInvoker) (*http.Response, error) {
			calls = append(calls, "a-before")
			req.Header.Set("A", "1")
			resp, err := invoker.Invoke(req)
			calls = append(calls, "a-after")
			resp.Header.Set("A", req.Header.Get("A"))
			return resp, err
		},
		func(ctx context.Context, req *http.Request, invoker HTTPDelegatedInvoker) (*http.Response, error) {
			calls = append(calls, "b-before")
			req.Header.Set("B", req.Header.Get("A")+"2")
			resp, err := invoker.Invoke(req)
			calls = append(calls, "b-after")
			resp.Header.Set("B", req.Header.Get("B"))
			return resp, err
		},
	}
	final := HTTPDelegatedInvokerFunc(func(req *http.Request) (*http.Response, error) {
		calls = append(calls, "final")
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header)}, nil
	})

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
	resp, err := chainHTTPInterceptors(interceptors)(context.Background(), req, final)
	if err != nil {
		t.Fatalf("chain returned error: %v", err)
	}
	if got, want := calls, []string{"a-before", "b-before", "final", "b-after", "a-after"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("calls = %#v; want %#v", got, want)
	}
	if resp.Header.Get("A") != "1" || resp.Header.Get("B") != "12" {
		t.Fatalf("response headers = %#v; want propagated interceptor values", resp.Header)
	}
}
