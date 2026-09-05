package mitmproxy

import (
	"io"
	"reflect"
	"strings"
	"testing"

	http "github.com/josexy/xhttp"
)

func TestHTTP2TrailerInitialBlockMatchesOrdinaryEncoding(t *testing.T) {
	observed := make(chan []http.HeaderField, 1)
	origin := startH2CWireOrigin(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.Copy(io.Discard, req.Body)
		for _, block := range http.RequestHeaderBlocks(req) {
			if block.Kind == http.HeaderBlockInitial {
				observed <- block.Fields
				break
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	protocols := &http.Protocols{}
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{Protocols: protocols, DisableCompression: true}
	defer transport.CloseIdleConnections()
	order := []string{":method", ":authority", ":path", ":scheme", "trailer", "cookie", "x-b", "x-a", "content-length", "te", "user-agent"}
	for _, test := range []struct {
		name, method, body string
		length             int64
		header             http.Header
	}{
		{name: "unknown_body", method: http.MethodPost, body: "payload", length: -1, header: http.Header{"Cookie": {"a=1; b=2", "c=3"}, "X-A": {"a"}, "X-B": {"b1", "b2"}, "Te": {"trailers"}}},
		{name: "fixed_body", method: http.MethodPut, body: "payload", length: 7, header: http.Header{"User-Agent": {"custom", "ignored"}, "Content-Length": {"999"}}},
		{name: "empty_post", method: http.MethodPost, header: http.Header{"User-Agent": nil}},
		{name: "empty_get", method: http.MethodGet, header: http.Header{"User-Agent": {""}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			var snapshots [][]http.HeaderField
			for _, exact := range []bool{false, true} {
				req, err := http.NewRequest(test.method, "http://"+origin+"/escaped%20path?q=1", strings.NewReader(test.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Host = "例子.example:8080"
				req.Header = test.header.Clone()
				req.ContentLength = test.length
				req.Trailer = http.Header{"X-A": {"a"}, "X-B": {"b"}}
				if exact {
					req, err = withHTTP2RequestTrailers(req, order)
				} else {
					req, err = http.WithRequestHeaderOrder(req, http.HeaderOrder{Headers: order})
				}
				if err != nil {
					t.Fatal(err)
				}
				resp, err := transport.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				_, err = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				snapshots = append(snapshots, receiveRegressionValue(t, observed))
			}
			if !reflect.DeepEqual(snapshots[0], snapshots[1]) {
				t.Errorf("initial headers changed:\nordinary: %#v\ntrailers: %#v", snapshots[0], snapshots[1])
			}
		})
	}
}
