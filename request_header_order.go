package mitmproxy

import (
	"errors"
	"fmt"
	"strings"

	http "github.com/josexy/xhttp"
	"golang.org/x/net/http/httpguts"
)

// WithRequestHeaderOrder returns a request whose upstream HTTP/1 or HTTP/2
// header and trailer blocks use order. Use this in an HTTPInterceptor and pass
// the returned request to the invoker.
//
// Names listed in a non-empty slice are written first, in that order. Other
// received fields keep their received relative order, and fields that were not
// received follow in lowercase lexical order. An empty slice keeps the received
// order for that block; an empty HeaderOrder clears a previous override.
// Matching is case-insensitive, missing names are ignored, and repeated values
// stay grouped. Headers may begin with the HTTP/2 pseudo-headers :method,
// :scheme, :authority, :path and :protocol, which HTTP/1 ignores. Trailers
// must contain valid trailer field names.
//
// Values always come from req.Header and req.Trailer, so editing a value never
// moves its field. HTTP/1 names are written as spelled in req.Header; use
// WithRequestHeaderBlock to control casing or interleave repeated fields. Both
// overrides may be combined, as described there.
//
// The override is carried by the returned shallow copy's context, so derive
// later contexts from it. xhttp.WithRequestHeaderOrder has no effect in an
// interceptor, because the proxy computes the upstream order itself.
// RequestWireHeaderOrder continues to report the original downstream order.
func WithRequestHeaderOrder(req *http.Request, order http.HeaderOrder) (*http.Request, error) {
	if req == nil {
		return nil, errors.New("mitmproxy: nil request")
	}
	override, err := normalizeSendingOrder(order, requestOrderPseudoHeaders)
	if err != nil {
		return nil, fmt.Errorf("mitmproxy: invalid request %w", err)
	}
	// Keep the override only in the proxy profile. Storing an xhttp order in
	// the context would conflict with the exact blocks the transport builds for
	// WithRequestHeaderBlock and HTTP/2 trailers, and xhttp cannot clear it.
	req = ensureRequestWireProfile(req)
	profile := *requestWireProfileFromRequest(req)
	profile.writeOrder = override
	return withRequestWireProfile(req, &profile), nil
}

var (
	requestOrderPseudoHeaders  = map[string]bool{":authority": true, ":method": true, ":path": true, ":protocol": true, ":scheme": true}
	responseOrderPseudoHeaders = map[string]bool{":status": true}
)

// normalizeSendingOrder validates and lowercases a sending override. It returns
// nil when both slices are empty, which clears an override.
func normalizeSendingOrder(order http.HeaderOrder, pseudos map[string]bool) (*http.HeaderOrder, error) {
	headers, err := normalizeSendingOrderNames(order.Headers, pseudos, false)
	if err != nil {
		return nil, fmt.Errorf("header order: %w", err)
	}
	trailers, err := normalizeSendingOrderNames(order.Trailers, nil, true)
	if err != nil {
		return nil, fmt.Errorf("trailer order: %w", err)
	}
	if len(headers) == 0 && len(trailers) == 0 {
		return nil, nil
	}
	return &http.HeaderOrder{Headers: headers, Trailers: trailers}, nil
}

func normalizeSendingOrderNames(names []string, pseudos map[string]bool, trailers bool) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	result := make([]string, len(names))
	seen := make(map[string]bool, len(names))
	regularSeen := false
	for i, name := range names {
		// Validate ASCII token syntax before lowercasing, so non-ASCII input
		// cannot become valid through Unicode case folding.
		if strings.HasPrefix(name, ":") {
			lower := strings.ToLower(name)
			if trailers || !httpguts.ValidHeaderFieldName(name[1:]) || !pseudos[lower] {
				return nil, fmt.Errorf("invalid pseudo-header %q", name)
			}
			if regularSeen {
				return nil, fmt.Errorf("pseudo-header %q appears after a regular field", name)
			}
			name = lower
		} else {
			if !httpguts.ValidHeaderFieldName(name) || (trailers && !httpguts.ValidTrailerHeader(name)) {
				return nil, fmt.Errorf("invalid field name %q", name)
			}
			regularSeen = true
			name = strings.ToLower(name)
		}
		if seen[name] {
			return nil, fmt.Errorf("duplicate field name %q", name)
		}
		seen[name] = true
		result[i] = name
	}
	return result, nil
}

// mergeSendingOrder lists override names first, then the received names it
// omits in their received order. Pseudo-headers stay ahead of regular names,
// as HTTP/2 requires. Both inputs are lowercase.
func mergeSendingOrder(override, received []string) []string {
	if len(override) == 0 {
		return append([]string(nil), received...)
	}
	listed := make(map[string]bool, len(override))
	for _, name := range override {
		listed[name] = true
	}
	result := make([]string, 0, len(override)+len(received))
	for _, pseudo := range []bool{true, false} {
		for _, name := range override {
			if strings.HasPrefix(name, ":") == pseudo {
				result = append(result, name)
			}
		}
		for _, name := range received {
			if strings.HasPrefix(name, ":") == pseudo && !listed[name] {
				result = append(result, name)
			}
		}
	}
	return result
}

func splitPseudoHeaderNames(names []string) (pseudos, regular []string) {
	for _, name := range names {
		if strings.HasPrefix(name, ":") {
			pseudos = append(pseudos, name)
		} else {
			regular = append(regular, name)
		}
	}
	return pseudos, regular
}
