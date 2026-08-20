package mitmproxy

import (
	"fmt"
	"runtime"
	"strings"
	"weak"

	http "github.com/josexy/xhttp"
)

const (
	http2NextProtoTLS  = "h2"
	http2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
)

func prepareHTTP2Request(req *http.Request) (*http.Request, error) {
	preparedReq := req.Clone(req.Context())
	preparedReq.RequestURI = ""
	// Request trailers are populated as the shared streaming body reaches EOF.
	preparedReq.Trailer = req.Trailer
	profile := requestWireProfileFromRequest(req)

	order := requestHeaderOrder(req)
	if profile != nil && profile.fingerprint == nil {
		pseudos := make([]string, 0, len(profile.headerOrder))
		for _, name := range profile.headerOrder {
			if strings.HasPrefix(name, ":") {
				pseudos = append(pseudos, name)
			}
		}
		order.Headers = append(pseudos, order.Headers...)
	}
	var err error
	if len(order.Headers) > 0 || len(order.Trailers) > 0 {
		preparedReq, err = http.WithRequestHeaderOrder(preparedReq, order)
		if err != nil {
			return nil, fmt.Errorf("apply HTTP/2 header order: %w", err)
		}
	}

	if profile != nil && profile.fingerprint != nil {
		fingerprint := upstreamHTTP2Fingerprint(*profile.fingerprint)
		fingerprint.PseudoHeaderOrder = compatiblePseudoHeaderOrder(preparedReq, fingerprint.PseudoHeaderOrder)
		preparedReq, err = http.WithRequestFingerprint(preparedReq, fingerprint)
		if err != nil {
			return nil, fmt.Errorf("apply HTTP/2 fingerprint: %w", err)
		}
	}
	return preparedReq, nil
}

func upstreamHTTP2Fingerprint(source http.Fingerprint) http.Fingerprint {
	fingerprint := cloneHTTP2Fingerprint(source)
	// Stream IDs are scoped to one HTTP/2 connection. Without a mapping from
	// downstream streams to independently allocated upstream streams, only a
	// dependency on the connection root can be replayed safely.
	if fingerprint.HeaderPriority != nil && fingerprint.HeaderPriority.StreamDep != 0 {
		fingerprint.HeaderPriority = nil
	}
	return fingerprint
}

func compatiblePseudoHeaderOrder(req *http.Request, captured []string) []string {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	required := map[string]bool{":authority": true, ":method": true}
	defaults := []string{":authority", ":method"}
	if method != http.MethodConnect {
		required[":path"] = true
		required[":scheme"] = true
		defaults = append(defaults, ":path", ":scheme")
	}

	result := make([]string, 0, len(required))
	seen := make(map[string]bool, len(required))
	appendName := func(name string) {
		name = strings.ToLower(name)
		if required[name] && !seen[name] {
			seen[name] = true
			result = append(result, name)
		}
	}
	for _, name := range captured {
		appendName(name)
	}
	for _, name := range defaults {
		appendName(name)
	}
	return result
}

func prepareHTTP2Response(resp *http.Response, req *http.Request) *http.Response {
	if resp == nil {
		return nil
	}
	resp.Request = req
	responseRef := weak.Make(resp)
	blocks := func() []http.HeaderBlock {
		response := responseRef.Value()
		if response == nil {
			return nil
		}
		blocks := http.ResponseHeaderBlocks(response)
		runtime.KeepAlive(response)
		return blocks
	}
	registerResponseWireProfile(resp, func() http.HeaderOrder {
		var order http.HeaderOrder
		for _, block := range blocks() {
			names := uniqueHeaderNames(block.Fields, true)
			switch block.Kind {
			case http.HeaderBlockInitial:
				if len(order.Headers) == 0 {
					order.Headers = names
				}
			case http.HeaderBlockTrailer:
				order.Trailers = names
			}
		}
		return order
	}, blocks)
	return resp
}
