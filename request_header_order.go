package mitmproxy

import (
	"errors"
	"strings"

	http "github.com/josexy/xhttp"
)

// WithRequestHeaderOrder returns a request whose upstream HTTP/1 or HTTP/2
// header and trailer blocks use order. Use this in an HTTPInterceptor after
// modifying the request and before invoking the upstream request.
//
// Each non-empty slice overrides the corresponding received block. Empty
// slices keep the received order. RequestWireHeaderOrder continues to report
// the original downstream order. The returned request is a shallow copy, and
// the caller must use it for the subsequent invoker call.
func WithRequestHeaderOrder(req *http.Request, order http.HeaderOrder) (*http.Request, error) {
	if req == nil {
		return nil, errors.New("mitmproxy: nil request")
	}
	prepared, err := http.WithRequestHeaderOrder(req, order)
	if err != nil {
		return nil, err
	}
	profile := requestWireProfileFromRequest(req)
	if profile == nil {
		profile = captureRequestWireProfile(req)
	}
	if profile == nil {
		return prepared, nil
	}
	profileCopy := *profile
	if len(order.Headers) == 0 && len(order.Trailers) == 0 {
		profileCopy.writeOrder = nil
	} else {
		profileCopy.writeOrder = &http.HeaderOrder{
			Headers:  normalizeRequestOrderNames(order.Headers),
			Trailers: normalizeRequestOrderNames(order.Trailers),
		}
	}
	return withRequestWireProfile(prepared, &profileCopy), nil
}

func normalizeRequestOrderNames(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	result := make([]string, len(names))
	for i, name := range names {
		result[i] = strings.ToLower(name)
	}
	return result
}
