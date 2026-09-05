package mitmproxy

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	http "github.com/josexy/xhttp"
	"golang.org/x/net/http/httpguts"
)

// xhttp's ordinary HeaderOrder is snapshotted before the body is read. Its
// deferred trailer API also requires an explicit initial block; construct that
// block from the outgoing request, never replay unsanitized inbound fields.
func withHTTP2RequestTrailers(req *http.Request, order []string) (*http.Request, error) {
	initial, err := http2RequestHeaderBlock(req, order)
	if err != nil {
		return nil, err
	}
	return http.WithRequestHeaderBlocks(req, initial, func() (http.HeaderBlock, error) {
		return trailerHeaderBlock(req.Trailer, RequestWireHeaderOrder(req).Trailers), nil
	})
}

func http2RequestHeaderBlock(req *http.Request, order []string) (http.HeaderBlock, error) {
	block := http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: 2}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	host, err := httpguts.PunycodeHostPort(host)
	if err != nil {
		return block, err
	}
	if !httpguts.ValidHostHeader(host) {
		return block, fmt.Errorf("invalid HTTP/2 authority %q", host)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	fields := map[string][]string{":authority": {host}, ":method": {method}}
	protocol := req.Header.Get(":protocol")
	if protocol != "" && method != http.MethodConnect {
		return block, fmt.Errorf("HTTP/2 :protocol requires CONNECT")
	}
	if method != http.MethodConnect || protocol != "" {
		path := req.URL.RequestURI()
		if !strings.HasPrefix(path, "/") && path != "*" {
			path = strings.TrimPrefix(path, req.URL.Scheme+"://"+host)
			if !strings.HasPrefix(path, "/") && path != "*" {
				return block, fmt.Errorf("invalid HTTP/2 path %q", path)
			}
		}
		fields[":path"] = []string{path}
		fields[":scheme"] = []string{req.URL.Scheme}
	}
	if protocol != "" {
		fields[":protocol"] = []string{protocol}
	}
	keys := make([]string, 0, len(req.Header))
	for name := range req.Header {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	didUserAgent := false
	for _, name := range keys {
		values := req.Header[name]
		if name == ":protocol" {
			continue
		}
		if !httpguts.ValidHeaderFieldName(name) {
			return block, fmt.Errorf("invalid HTTP/2 header name %q", name)
		}
		for _, value := range values {
			if !httpguts.ValidHeaderFieldValue(value) {
				return block, fmt.Errorf("invalid HTTP/2 header value for %q", name)
			}
		}
		name = strings.ToLower(name)
		switch name {
		case "host", "content-length", "trailer", "connection", "proxy-connection", "transfer-encoding", "upgrade", "keep-alive":
			continue
		case "user-agent":
			didUserAgent = true
			if len(values) == 0 || values[0] == "" {
				continue
			}
			values = values[:1]
		case "cookie":
			var cookies []string
			for _, value := range values {
				parts := strings.Split(value, ";")
				for i, part := range parts {
					if i > 0 {
						part = strings.TrimLeft(part, " ")
					}
					if part != "" {
						cookies = append(cookies, part)
					}
				}
			}
			values = cookies
		}
		fields[name] = append(fields[name], values...)
	}
	if !didUserAgent {
		fields["user-agent"] = []string{"Go-http-client/2.0"}
	}
	length := req.ContentLength
	if req.Body == nil || req.Body == http.NoBody {
		length = 0
	} else if length == 0 {
		length = -1
	}
	if length > 0 || (length == 0 && (method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch)) {
		fields["content-length"] = []string{strconv.FormatInt(length, 10)}
	}
	var trailers []string
	for name := range req.Trailer {
		if !httpguts.ValidHeaderFieldName(name) || !httpguts.ValidTrailerHeader(name) {
			return block, fmt.Errorf("invalid HTTP/2 trailer name %q", name)
		}
		trailers = append(trailers, http.CanonicalHeaderKey(name))
	}
	if len(trailers) > 0 {
		sort.Strings(trailers)
		fields["trailer"] = []string{strings.Join(trailers, ",")}
	}
	emit := func(name string) {
		for _, value := range fields[name] {
			block.Fields = append(block.Fields, http.HeaderField{Name: name, Value: value})
		}
		delete(fields, name)
	}
	for _, name := range compatiblePseudoHeaderOrder(req, order) {
		emit(name)
	}
	for _, name := range order {
		emit(strings.ToLower(name))
	}
	keys = keys[:0]
	for name := range fields {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	for _, name := range keys {
		emit(name)
	}
	return block, nil
}
