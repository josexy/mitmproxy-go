package mitmproxy

import (
	"errors"
	"fmt"
	"runtime"
	"weak"

	http "github.com/josexy/xhttp"
)

// SetResponseHeaderOrder configures the header and trailer order used when the
// proxy sends response to the downstream client over HTTP/1 or HTTP/2. Call it
// in an HTTPInterceptor before returning the response. It also works on locally
// constructed responses; no ResponseWriter is required.
//
// Names listed in a non-empty slice are written first, in that order. Other
// received fields keep their received relative order, including trailers that
// arrive at Body EOF, and fields that were not received follow in lowercase
// lexical order. An empty slice keeps the received order for that block. Each
// call replaces the previous override; an empty HeaderOrder clears it.
// Matching is case-insensitive, missing names are ignored, and repeated values
// stay grouped. An optional :status may appear first in Headers; HTTP/1
// ignores it. No other pseudo-header is allowed, and Trailers must contain
// valid trailer field names. SetResponseHeaderBlock may be combined with this
// order, as described there.
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
	override, err := normalizeSendingOrder(order, responseOrderPseudoHeaders)
	if err != nil {
		return fmt.Errorf("mitmproxy: invalid response %w", err)
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
