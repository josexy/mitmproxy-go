package mitmproxy

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"weak"

	http "github.com/josexy/xhttp"
	"github.com/josexy/xhttp/httptrace"
	"golang.org/x/net/http/httpguts"
)

// WithRequestHeaderBlock configures the layout of the upstream initial header
// block, including HTTP/1 name casing and interleaved repeated fields. Unlike
// xhttp.WithRequestHeaderBlocks, block is a layout rather than a complete wire
// block: req.Header stays the source of values, and Host, pseudo-header values,
// framing and hop-by-hop sanitization stay owned by the proxy.
//
// Each block field reserves one position for its name. A current value equal
// to a block value takes that position; other current values of the same name
// fill that name's remaining positions in order, so editing a value in
// req.Header keeps its position. Removed fields are not resurrected. Fields
// without a position follow in the WithRequestHeaderOrder order: its override
// if any, then the received order, then lowercase lexical order. Names match
// case-insensitively; a position supplies the HTTP/1 spelling and the HTTP/2
// Sensitive flag. Kind must be HeaderBlockInitial and Truncated false;
// ProtoMajor and StatusCode are ignored, so a captured block of either protocol
// may be reused. The input is copied, the latest call replaces an earlier one,
// and RequestWireHeaderBlocks still reports the received blocks.
//
// The layout is carried by the returned shallow copy's context. Use this
// function, not xhttp.WithRequestHeaderBlocks, in an interceptor: the invoker
// rejects xhttp exact blocks because they would bypass header sanitization.
func WithRequestHeaderBlock(req *http.Request, block http.HeaderBlock) (*http.Request, error) {
	if req == nil {
		return nil, errors.New("mitmproxy: nil request")
	}
	if err := validateSendingBlock(block, false); err != nil {
		return nil, err
	}
	req = ensureRequestWireProfile(req)
	profile := *requestWireProfileFromRequest(req)
	block.Fields = append([]http.HeaderField(nil), block.Fields...)
	profile.writeBlock = &block
	return withRequestWireProfile(req, &profile), nil
}

// SetResponseHeaderBlock configures the layout of the downstream initial header
// block with the same rules as WithRequestHeaderBlock; fields without a
// position follow the SetResponseHeaderOrder order. Status, body framing and
// hop-by-hop sanitization remain authoritative, and ResponseWireHeaderBlocks
// still reports the received blocks. Call it before returning response from an
// interceptor; a copied or replaced response must be configured again.
func SetResponseHeaderBlock(response *http.Response, block http.HeaderBlock) error {
	if response == nil {
		return errors.New("mitmproxy: nil response")
	}
	if err := validateSendingBlock(block, true); err != nil {
		return err
	}
	block.Fields = append([]http.HeaderField(nil), block.Fields...)
	updateResponseProfile(response, func(profile *responseWireProfile) { profile.writeBlock = &block })
	return nil
}

func updateResponseProfile(response *http.Response, update func(*responseWireProfile)) {
	key := weak.Make(response)
	responseWireProfiles.Lock()
	profile, registered := responseWireProfiles.m[key]
	update(&profile)
	responseWireProfiles.m[key] = profile
	responseWireProfiles.Unlock()
	if !registered {
		runtime.AddCleanup(response, removeResponseWireProfile, key)
	}
	runtime.KeepAlive(response)
}

func validateSendingBlock(block http.HeaderBlock, response bool) error {
	if block.Kind != http.HeaderBlockInitial || block.Truncated {
		return errors.New("mitmproxy: sending override requires a complete initial HeaderBlock")
	}
	for _, field := range block.Fields {
		if strings.HasPrefix(field.Name, ":") {
			if response && field.Name != ":status" {
				return fmt.Errorf("mitmproxy: invalid response pseudo-header %q", field.Name)
			}
			if !response && field.Name != ":method" && field.Name != ":scheme" && field.Name != ":authority" && field.Name != ":path" && field.Name != ":protocol" {
				return fmt.Errorf("mitmproxy: invalid request pseudo-header %q", field.Name)
			}
		} else if !httpguts.ValidHeaderFieldName(field.Name) {
			return fmt.Errorf("mitmproxy: invalid header name %q", field.Name)
		}
		if !httpguts.ValidHeaderFieldValue(field.Value) {
			return fmt.Errorf("mitmproxy: invalid header value for %q", field.Name)
		}
	}
	return nil
}

// orderedSendingFields lays out fields according to order. Each order entry is
// a position for one occurrence of its name. Positions are first filled by
// fields with an equal value, then by the remaining fields of the same name in
// their current order, so an edited value keeps its position. Structural values
// are matched by name because they are regenerated from the request/response
// rather than trusted from a potentially stale override. Unplaced fields keep
// their incoming order after the placed ones.
func orderedSendingFields(fields, order []http.HeaderField, proto int) []http.HeaderField {
	assigned := make([]int, len(order))
	used := make([]bool, len(fields))
	for i := range assigned {
		assigned[i] = -1
	}
	assign := func(exactValue bool) {
		for i, want := range order {
			// HTTP/1 has no pseudo-headers; a reused HTTP/2 layout lists them.
			if assigned[i] >= 0 || (proto != 2 && strings.HasPrefix(want.Name, ":")) {
				continue
			}
			for j, field := range fields {
				if used[j] || !strings.EqualFold(want.Name, field.Name) {
					continue
				}
				if exactValue && want.Value != field.Value && !structuralSendingField(field.Name) {
					continue
				}
				assigned[i], used[j] = j, true
				break
			}
		}
	}
	assign(true)
	assign(false)

	result := make([]http.HeaderField, 0, len(fields))
	emit := func(pseudo bool) {
		for i, want := range order {
			if assigned[i] < 0 || strings.HasPrefix(want.Name, ":") != pseudo {
				continue
			}
			field := fields[assigned[i]]
			if proto == 1 {
				field.Name = want.Name
			} else {
				field.Name = strings.ToLower(field.Name)
				field.Sensitive = want.Sensitive
			}
			result = append(result, field)
		}
	}
	// HTTP/2 requires every pseudo-header before every regular field.
	if proto == 2 {
		emit(true)
		for j, field := range fields {
			if !used[j] && strings.HasPrefix(field.Name, ":") {
				used[j] = true
				result = append(result, field)
			}
		}
	}
	emit(false)
	for j, field := range fields {
		if !used[j] {
			result = append(result, field)
		}
	}
	return result
}

// sortSendingFields stably orders regular fields by names: listed names first
// in that order, then the rest in lowercase lexical order. Pseudo-headers stay
// first in their current order, and repeated names keep their relative order.
func sortSendingFields(fields []http.HeaderField, names []string) {
	positions := make(map[string]int, len(names))
	for index, name := range names {
		name = strings.ToLower(name)
		if !strings.HasPrefix(name, ":") {
			positions[name] = index
		}
	}
	// Resolve each spelling once instead of allocating lowercase strings on
	// every comparison.
	type fieldRank struct {
		pseudo   bool
		name     string
		position int
	}
	ranks := make(map[string]fieldRank, len(fields))
	for _, field := range fields {
		if _, ok := ranks[field.Name]; ok {
			continue
		}
		name := strings.ToLower(field.Name)
		position, listed := positions[name]
		if !listed {
			position = len(names)
		}
		ranks[field.Name] = fieldRank{strings.HasPrefix(name, ":"), name, position}
	}
	slices.SortStableFunc(fields, func(a, b http.HeaderField) int {
		left, right := ranks[a.Name], ranks[b.Name]
		if left.pseudo || right.pseudo {
			if left.pseudo == right.pseudo {
				return 0
			}
			if left.pseudo {
				return -1
			}
			return 1
		}
		if result := cmp.Compare(left.position, right.position); result != 0 {
			return result
		}
		return strings.Compare(left.name, right.name)
	})
}

func structuralSendingField(name string) bool {
	if strings.HasPrefix(name, ":") {
		return true
	}
	switch strings.ToLower(name) {
	case "host", "content-length", "transfer-encoding", "trailer", "connection":
		return true
	}
	return false
}

func sortedSendingFields(header http.Header, proto int) []http.HeaderField {
	keys := make([]string, 0, len(header))
	for key := range header {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var fields []http.HeaderField
	for _, key := range keys {
		name := key
		if proto == 2 {
			name = strings.ToLower(name)
		}
		for _, value := range header[key] {
			fields = append(fields, http.HeaderField{Name: name, Value: value})
		}
	}
	return fields
}

func withExactRequestHeaderBlock(req *http.Request, proto int) (*http.Request, error) {
	profile := requestWireProfileFromRequest(req)
	if profile == nil || profile.writeBlock == nil {
		return req, nil
	}
	block := http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: proto}
	if proto == 2 {
		generated, err := http2RequestHeaderBlock(req, requestPseudoHeaderOrder(profile))
		if err != nil {
			return nil, err
		}
		for _, field := range generated.Fields {
			if structuralSendingField(field.Name) || (field.Name == "user-agent" && !sendingHeaderContains(req.Header, "User-Agent")) {
				block.Fields = append(block.Fields, field)
			}
		}
	} else {
		host := req.Host
		if host == "" {
			host = req.URL.Host
		}
		block.Fields = append(block.Fields, http.HeaderField{Name: "Host", Value: host})
		if req.Body != nil && req.Body != http.NoBody && req.ContentLength <= 0 || len(req.TransferEncoding) > 0 || len(req.Trailer) > 0 {
			prepared := new(http.Request)
			*prepared = *req
			req = prepared
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
			block.Fields = append(block.Fields, http.HeaderField{Name: "Transfer-Encoding", Value: "chunked"})
			if len(req.Trailer) > 0 {
				names := make([]string, 0, len(req.Trailer))
				for name := range req.Trailer {
					names = append(names, name)
				}
				sort.Strings(names)
				block.Fields = append(block.Fields, http.HeaderField{Name: "Trailer", Value: strings.Join(names, ", ")})
			}
		} else if req.ContentLength > 0 || req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch {
			block.Fields = append(block.Fields, http.HeaderField{Name: "Content-Length", Value: strconv.FormatInt(max(0, req.ContentLength), 10)})
		}
		if req.Close {
			block.Fields = append(block.Fields, http.HeaderField{Name: "Connection", Value: "close"})
		}
		if !sendingHeaderContains(req.Header, "User-Agent") {
			block.Fields = append(block.Fields, http.HeaderField{Name: "User-Agent", Value: "Go-http-client/1.1"})
		}
	}
	for _, field := range sortedSendingFields(req.Header, proto) {
		if !structuralSendingField(field.Name) {
			block.Fields = append(block.Fields, field)
		}
	}
	sortSendingFields(block.Fields, requestHeaderOrder(req).Headers)
	block.Fields = orderedSendingFields(block.Fields, profile.writeBlock.Fields, proto)
	var trailers http.HeaderBlockFunc
	if len(req.Trailer) > 0 {
		trailers = func() (http.HeaderBlock, error) {
			block := trailerHeaderBlock(req.Trailer, requestHeaderOrder(req).Trailers)
			block.ProtoMajor = proto
			return block, nil
		}
	}
	if proto == 2 {
		if fingerprint, ok := http.RequestFingerprint(req); ok {
			fingerprint.PseudoHeaderOrder = nil
			for _, field := range block.Fields {
				if strings.HasPrefix(field.Name, ":") {
					fingerprint.PseudoHeaderOrder = append(fingerprint.PseudoHeaderOrder, field.Name)
				}
			}
			var err error
			req, err = http.WithRequestFingerprint(req, fingerprint)
			if err != nil {
				return nil, err
			}
		}
	}
	prepared, err := http.WithRequestHeaderBlocks(req, block, trailers)
	if err == nil {
		if observation := requestSendHeaderObservationFrom(prepared); observation != nil {
			observation.setExact(block)
		}
	}
	return prepared, err
}

func responseSendingBlock(response *http.Response, proto int) (http.HeaderBlock, bool) {
	profile, ok := responseWireProfileFor(response)
	if !ok || profile.writeBlock == nil {
		return http.HeaderBlock{}, false
	}
	fields := sortedSendingFields(response.Header, proto)
	if proto == 2 {
		// Exact blocks bypass the server's framing generation. Never let a
		// stale/interceptor Content-Length disagree with the final body.
		filtered := fields[:0]
		for _, field := range fields {
			if !strings.EqualFold(field.Name, "content-length") {
				filtered = append(filtered, field)
			}
		}
		fields = filtered
		if response.ContentLength >= 0 && (http1ResponseBodyAllowed(response.Request, response.StatusCode) || (response.Request != nil && response.Request.Method == http.MethodHead)) {
			fields = append(fields, http.HeaderField{Name: "content-length", Value: strconv.FormatInt(response.ContentLength, 10)})
		}
		fields = append([]http.HeaderField{{Name: ":status", Value: strconv.Itoa(response.StatusCode)}}, fields...)
	}
	status := 0
	if proto == 1 {
		status = response.StatusCode
	}
	sortSendingFields(fields, responseHeaderOrder(response).Headers)
	return http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: proto, StatusCode: status, Fields: orderedSendingFields(fields, profile.writeBlock.Fields, proto)}, true
}

func sendingHeaderContains(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// WithHTTPRequestSendHeaderObserver returns a request copy whose observer
// receives each initial header block the transport writes upstream, with or
// without header order or layout overrides. It is called once per write
// attempt, after the last header field has been written and before the body,
// on the goroutine writing the request; a retried request reports every
// attempt that wrote its headers. Blocks are caller-owned, record the upstream
// protocol in ProtoMajor, and contain the sanitized fields as written: HTTP/1
// names keep their written spelling, HTTP/2 names are lowercase with
// pseudo-headers first. Sensitive is reported for WithRequestHeaderBlock
// layouts. Observation never alters the request or received metadata.
func WithHTTPRequestSendHeaderObserver(req *http.Request, observer func(http.HeaderBlock)) *http.Request {
	req = ensureRequestWireProfile(req)
	profile := *requestWireProfileFromRequest(req)
	profile.sendHeaderObserver = observer
	return withRequestWireProfile(req, &profile)
}

type requestSendHeaderObservationKey struct{}

// requestSendHeaderObservation assembles written fields from httptrace
// callbacks for one upstream round trip. Retries reset it at each attempt.
type requestSendHeaderObservation struct {
	observer func(http.HeaderBlock)
	proto    int
	mu       sync.Mutex
	fields   []http.HeaderField
	exact    *http.HeaderBlock
}

// observeRequestSendHeaders attaches header write tracing once per round trip
// when the request has a send-header observer.
func observeRequestSendHeaders(req *http.Request, proto int) *http.Request {
	profile := requestWireProfileFromRequest(req)
	if profile == nil || profile.sendHeaderObserver == nil || requestSendHeaderObservationFrom(req) != nil {
		return req
	}
	observation := &requestSendHeaderObservation{observer: profile.sendHeaderObserver, proto: proto}
	ctx := context.WithValue(req.Context(), requestSendHeaderObservationKey{}, observation)
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteHeaderField: observation.wroteHeaderField,
		WroteHeaders:     observation.wroteHeaders,
	})
	return req.WithContext(ctx)
}

func requestSendHeaderObservationFrom(req *http.Request) *requestSendHeaderObservation {
	if req == nil {
		return nil
	}
	observation, _ := req.Context().Value(requestSendHeaderObservationKey{}).(*requestSendHeaderObservation)
	return observation
}

// setExact records the layout block written verbatim, so the report keeps its
// HTTP/2 Sensitive flags, which httptrace does not expose.
func (o *requestSendHeaderObservation) setExact(block http.HeaderBlock) {
	block = cloneSendingBlock(block)
	o.mu.Lock()
	o.exact = &block
	o.mu.Unlock()
}

// reset discards fields from an attempt that failed before its headers were
// complete.
func (o *requestSendHeaderObservation) reset() {
	o.mu.Lock()
	o.fields = nil
	o.mu.Unlock()
}

func (o *requestSendHeaderObservation) wroteHeaderField(name string, values []string) {
	o.mu.Lock()
	for _, value := range values {
		o.fields = append(o.fields, http.HeaderField{Name: name, Value: value})
	}
	o.mu.Unlock()
}

func (o *requestSendHeaderObservation) wroteHeaders() {
	o.mu.Lock()
	block := http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: o.proto, Fields: o.fields}
	if o.exact != nil {
		block = cloneSendingBlock(*o.exact)
	}
	o.fields = nil
	o.mu.Unlock()
	// Never call the application callback under the observation lock.
	o.observer(block)
}

func resetRequestSendHeaderObservation(req *http.Request) {
	if observation := requestSendHeaderObservationFrom(req); observation != nil {
		observation.reset()
	}
}

func cloneSendingBlock(block http.HeaderBlock) http.HeaderBlock {
	block.Fields = append([]http.HeaderField(nil), block.Fields...)
	return block
}
