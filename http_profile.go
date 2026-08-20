package mitmproxy

import (
	"context"
	"runtime"
	"sort"
	"strings"
	"sync"
	"weak"

	http "github.com/josexy/xhttp"
	"golang.org/x/net/http/httpguts"
)

type requestWireProfileContextKey struct{}

// headerOrderSnapshotProvider returns a fresh caller-owned snapshot on every
// invocation, including fresh Headers and Trailers slices.
type headerOrderSnapshotProvider func() http.HeaderOrder

// headerBlockSnapshotProvider returns a fresh caller-owned snapshot on every
// invocation, including fresh nested Fields slices.
type headerBlockSnapshotProvider func() []http.HeaderBlock

type responseWireProfile struct {
	order  headerOrderSnapshotProvider
	blocks headerBlockSnapshotProvider
}

var responseWireProfiles = struct {
	sync.RWMutex
	m map[weak.Pointer[http.Response]]responseWireProfile
}{m: make(map[weak.Pointer[http.Response]]responseWireProfile)}

func responseWireProfileFor(response *http.Response) (responseWireProfile, bool) {
	if response == nil {
		return responseWireProfile{}, false
	}
	key := weak.Make(response)
	responseWireProfiles.RLock()
	profile, ok := responseWireProfiles.m[key]
	responseWireProfiles.RUnlock()
	runtime.KeepAlive(response)
	return profile, ok
}

// requestWireProfile is captured before Request.WithContext can detach the
// request from xhttp's pointer-associated receive blocks. Values remain owned
// by this profile for the lifetime of one proxied request.
type requestWireProfile struct {
	headerOrder  []string
	trailerOrder []string
	fingerprint  *http.Fingerprint
	blocks       headerBlockSnapshotProvider
}

func ensureRequestWireProfile(req *http.Request) *http.Request {
	if req == nil || requestWireProfileFromRequest(req) != nil {
		return req
	}
	return withRequestWireProfile(req, captureRequestWireProfile(req))
}

func captureRequestWireProfile(req *http.Request) *requestWireProfile {
	if req == nil {
		return nil
	}
	profile := &requestWireProfile{
		blocks: func() []http.HeaderBlock {
			return http.RequestHeaderBlocks(req)
		},
	}
	capturedInitial := false

	for _, block := range profile.blocks() {
		switch block.Kind {
		case http.HeaderBlockInitial:
			if !capturedInitial {
				capturedInitial = true
				profile.headerOrder = uniqueHeaderNames(block.Fields, true)
				profile.trailerOrder = declaredTrailerOrder(block.Fields)
			}
		case http.HeaderBlockTrailer:
			profile.trailerOrder = uniqueHeaderNames(block.Fields, false)
		}
	}
	if fingerprint, ok := http.RequestFingerprint(req); ok {
		profile.fingerprint = &fingerprint
	}
	return profile
}

func withRequestWireProfile(req *http.Request, profile *requestWireProfile) *http.Request {
	if req == nil || profile == nil {
		return req
	}
	ctx := context.WithValue(req.Context(), requestWireProfileContextKey{}, profile)
	return req.WithContext(ctx)
}

func requestWireProfileFromRequest(req *http.Request) *requestWireProfile {
	if req == nil {
		return nil
	}
	profile, _ := req.Context().Value(requestWireProfileContextKey{}).(*requestWireProfile)
	return profile
}

func cloneHTTP2Fingerprint(fingerprint http.Fingerprint) http.Fingerprint {
	fingerprint.Settings = append([]http.Setting(nil), fingerprint.Settings...)
	fingerprint.Priorities = append([]http.FingerprintPriority(nil), fingerprint.Priorities...)
	if fingerprint.HeaderPriority != nil {
		headerPriority := *fingerprint.HeaderPriority
		fingerprint.HeaderPriority = &headerPriority
	}
	fingerprint.PseudoHeaderOrder = append([]string(nil), fingerprint.PseudoHeaderOrder...)
	return fingerprint
}

func cloneHeaderBlocks(blocks []http.HeaderBlock) []http.HeaderBlock {
	if len(blocks) == 0 {
		return nil
	}
	cloned := make([]http.HeaderBlock, len(blocks))
	copy(cloned, blocks)
	for i := range cloned {
		cloned[i].Fields = append([]http.HeaderField(nil), blocks[i].Fields...)
	}
	return cloned
}

func uniqueHeaderNames(fields []http.HeaderField, includePseudo bool) []string {
	names := make([]string, 0, len(fields))
	seen := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		name := strings.ToLower(field.Name)
		if name == "" || (!includePseudo && strings.HasPrefix(name, ":")) {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func declaredTrailerOrder(fields []http.HeaderField) []string {
	var names []string
	seen := make(map[string]struct{})
	for _, field := range fields {
		if !strings.EqualFold(field.Name, "trailer") {
			continue
		}
		for _, value := range strings.Split(field.Value, ",") {
			name := strings.ToLower(strings.TrimSpace(value))
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names
}

// RequestWireHeaderOrder returns a defensive snapshot of the request header
// and trailer order observed on the inbound connection. HTTP/2 pseudo-headers
// are retained in Headers.
func RequestWireHeaderOrder(req *http.Request) http.HeaderOrder {
	profile := requestWireProfileFromRequest(req)
	if profile == nil {
		profile = captureRequestWireProfile(req)
	}
	if profile == nil {
		return http.HeaderOrder{}
	}
	order := http.HeaderOrder{
		Headers:  append([]string(nil), profile.headerOrder...),
		Trailers: append([]string(nil), profile.trailerOrder...),
	}
	for _, block := range RequestWireHeaderBlocks(req) {
		if block.Kind == http.HeaderBlockTrailer {
			order.Trailers = uniqueHeaderNames(block.Fields, false)
		}
	}
	return order
}

// ResponseWireHeaderOrder returns a defensive snapshot of the response header
// and trailer order observed on the upstream connection. HTTP/2 pseudo-headers
// are retained in Headers.
func ResponseWireHeaderOrder(response *http.Response) http.HeaderOrder {
	return responseHeaderOrder(response)
}

// RequestHTTP2Fingerprint returns a defensive snapshot of the HTTP/2 client
// fingerprint observed on the inbound connection.
func RequestHTTP2Fingerprint(req *http.Request) (http.Fingerprint, bool) {
	if req == nil {
		return http.Fingerprint{}, false
	}
	profile := requestWireProfileFromRequest(req)
	if profile != nil && profile.fingerprint != nil {
		return cloneHTTP2Fingerprint(*profile.fingerprint), true
	}
	fingerprint, ok := http.RequestFingerprint(req)
	if !ok {
		return http.Fingerprint{}, false
	}
	return fingerprint, true
}

// RequestWireHeaderBlocks returns defensive snapshots of all request header
// blocks currently available, including informationally late trailer blocks.
func RequestWireHeaderBlocks(req *http.Request) []http.HeaderBlock {
	if req == nil {
		return nil
	}
	if profile := requestWireProfileFromRequest(req); profile != nil && profile.blocks != nil {
		return profile.blocks()
	}
	return http.RequestHeaderBlocks(req)
}

// ResponseWireHeaderBlocks returns defensive snapshots of all response header
// blocks currently available, including informational and trailer blocks.
func ResponseWireHeaderBlocks(response *http.Response) []http.HeaderBlock {
	if response == nil {
		return nil
	}
	if profile, ok := responseWireProfileFor(response); ok {
		if profile.blocks != nil {
			return profile.blocks()
		}
	}
	return http.ResponseHeaderBlocks(response)
}

func requestHeaderOrder(req *http.Request) http.HeaderOrder {
	profile := requestWireProfileFromRequest(req)
	if profile == nil {
		return http.HeaderOrder{}
	}
	headers := make([]string, 0, len(profile.headerOrder))
	for _, name := range profile.headerOrder {
		if !strings.HasPrefix(name, ":") {
			headers = append(headers, name)
		}
	}
	return http.HeaderOrder{
		Headers:  headers,
		Trailers: append([]string(nil), profile.trailerOrder...),
	}
}

func withRequestHeaderOrder(req *http.Request) (*http.Request, error) {
	order := requestHeaderOrder(req)
	if len(order.Headers) == 0 && len(order.Trailers) == 0 {
		return req, nil
	}
	return http.WithRequestHeaderOrder(req, order)
}

func responseHeaderOrder(response *http.Response) http.HeaderOrder {
	if response == nil {
		return http.HeaderOrder{}
	}
	if profile, ok := responseWireProfileFor(response); ok {
		if order := profile.order; order != nil {
			return order()
		}
	}
	var order http.HeaderOrder
	for _, block := range ResponseWireHeaderBlocks(response) {
		switch block.Kind {
		case http.HeaderBlockInitial:
			if len(order.Headers) == 0 {
				order.Headers = uniqueHeaderNames(block.Fields, true)
			}
		case http.HeaderBlockTrailer:
			order.Trailers = uniqueHeaderNames(block.Fields, false)
		}
	}
	return order
}

func registerResponseWireProfile(response *http.Response, order headerOrderSnapshotProvider, blockProviders ...headerBlockSnapshotProvider) {
	if response == nil {
		return
	}
	var blocks headerBlockSnapshotProvider
	if len(blockProviders) > 0 {
		blocks = blockProviders[0]
	}
	if order != nil || blocks != nil {
		key := weak.Make(response)
		responseWireProfiles.Lock()
		responseWireProfiles.m[key] = responseWireProfile{order: order, blocks: blocks}
		responseWireProfiles.Unlock()
		runtime.AddCleanup(response, func(key weak.Pointer[http.Response]) {
			responseWireProfiles.Lock()
			delete(responseWireProfiles.m, key)
			responseWireProfiles.Unlock()
		}, key)
	}
}

func unregisterResponseWireProfile(response *http.Response) {
	if response == nil {
		return
	}
	key := weak.Make(response)
	responseWireProfiles.Lock()
	delete(responseWireProfiles.m, key)
	responseWireProfiles.Unlock()
	runtime.KeepAlive(response)
}

func responseTrailerHeaderBlock(response *http.Response) http.HeaderBlock {
	block := http.HeaderBlock{Kind: http.HeaderBlockTrailer, ProtoMajor: 2}
	if response == nil || len(response.Trailer) == 0 {
		return block
	}
	order := responseHeaderOrder(response).Trailers
	values := make(map[string][]string, len(response.Trailer))
	keys := make([]string, 0, len(response.Trailer))
	for name := range response.Trailer {
		keys = append(keys, name)
	}
	sort.Slice(keys, func(i, j int) bool {
		left, right := strings.ToLower(keys[i]), strings.ToLower(keys[j])
		if left == right {
			return keys[i] < keys[j]
		}
		return left < right
	})
	for _, name := range keys {
		lower := strings.ToLower(name)
		if !httpguts.ValidTrailerHeader(lower) {
			continue
		}
		values[lower] = append(values[lower], response.Trailer[name]...)
	}

	emitted := make(map[string]bool, len(values))
	emit := func(name string) {
		name = strings.ToLower(name)
		if emitted[name] {
			return
		}
		emitted[name] = true
		for _, value := range values[name] {
			block.Fields = append(block.Fields, http.HeaderField{Name: name, Value: value})
		}
	}
	for _, name := range order {
		emit(name)
	}
	remaining := make([]string, 0, len(values))
	for name := range values {
		if !emitted[name] {
			remaining = append(remaining, name)
		}
	}
	sort.Strings(remaining)
	for _, name := range remaining {
		emit(name)
	}
	return block
}
