package mitmproxy

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"weak"

	http "github.com/josexy/xhttp"
	"golang.org/x/net/http/httpguts"
)

// SetResponseHeaderOrder configures the header and trailer order used when the
// proxy sends response to the downstream client over HTTP/1 or HTTP/2. Call it
// in an HTTPInterceptor before returning the response. It also works on locally
// constructed responses; no ResponseWriter is required.
//
// Each non-empty slice overrides the received order for that block. Empty
// slices inherit the received order, including trailers arriving at Body EOF.
// Each call replaces the previous override; an empty HeaderOrder clears it.
// Matching is case-insensitive, missing names are ignored, repeated values stay
// grouped, and unlisted fields follow in lowercase lexical order. An optional
// :status may appear first in Headers; HTTP/1 ignores it. No other pseudo-header
// is allowed, and Trailers must contain valid trailer field names.
//
// The order is validated and copied before publication; errors leave any prior
// configuration unchanged. Header values, Body, framing and hop-by-hop filtering
// are unaffected. ResponseWireHeaderOrder and ResponseWireHeaderBlocks continue
// to describe the received traffic, not this sending override.
//
// Configuration is tied to this response pointer and is released when it is
// garbage-collected. If an interceptor replaces or copies the response, it must
// configure the replacement. Configuration access is synchronized, but callers
// must still synchronize mutations of the response itself and finish configuring
// it before downstream writing begins.
func SetResponseHeaderOrder(response *http.Response, order http.HeaderOrder) error {
	if response == nil {
		return errors.New("mitmproxy: nil response")
	}
	headers, err := normalizeResponseOrderNames(order.Headers, false)
	if err != nil {
		return fmt.Errorf("mitmproxy: invalid response header order: %w", err)
	}
	trailers, err := normalizeResponseOrderNames(order.Trailers, true)
	if err != nil {
		return fmt.Errorf("mitmproxy: invalid response trailer order: %w", err)
	}
	var override *http.HeaderOrder
	if len(headers) > 0 || len(trailers) > 0 {
		override = &http.HeaderOrder{Headers: headers, Trailers: trailers}
	}
	key := weak.Make(response)
	responseWireProfiles.Lock()
	profile, registered := responseWireProfiles.m[key]
	if registered || override != nil {
		profile.writeOrder = override
		responseWireProfiles.m[key] = profile
	}
	responseWireProfiles.Unlock()
	// Updating or clearing an existing entry reuses its cleanup. The value
	// contains no response reference, so the weak registry cannot keep it alive.
	if !registered && override != nil {
		runtime.AddCleanup(response, removeResponseWireProfile, key)
	}
	runtime.KeepAlive(response)
	return nil
}

func normalizeResponseOrderNames(names []string, trailers bool) ([]string, error) {
	if len(names) == 0 {
		return nil, nil
	}
	result := make([]string, len(names))
	seen := make(map[string]bool, len(names))
	for i, name := range names {
		// Validate ASCII token syntax before lowercasing, so non-ASCII input
		// cannot become valid through Unicode case folding.
		if strings.HasPrefix(name, ":") {
			if trailers || i != 0 || strings.ToLower(name) != ":status" {
				return nil, fmt.Errorf("invalid pseudo-header %q", name)
			}
		} else if !httpguts.ValidHeaderFieldName(name) || (trailers && !httpguts.ValidTrailerHeader(name)) {
			return nil, fmt.Errorf("invalid field name %q", name)
		}
		name = strings.ToLower(name)
		if seen[name] {
			return nil, fmt.Errorf("duplicate field name %q", name)
		}
		seen[name] = true
		result[i] = name
	}
	return result, nil
}
