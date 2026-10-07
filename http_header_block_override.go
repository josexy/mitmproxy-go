package mitmproxy

import (
	"bytes"
	"errors"
	"fmt"
	"net/textproto"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"weak"

	http "github.com/josexy/xhttp"
	"golang.org/x/net/http/httpguts"
)

// WithRequestHeaderBlock configures the exact outgoing initial-field sequence.
// Fields are matched against the final Header values (case-insensitively by
// name); removed or changed fields cannot be resurrected. Remaining fields are
// appended deterministically. Host/pseudo-headers and framing remain owned by
// the transport. Duplicate fields, their interleaving, casing (HTTP/1) and empty
// values are retained. The received RequestWireHeaderBlocks are unaffected.
// Configure Header and this override before Invoke. The input is copied.
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

// SetResponseHeaderBlock configures the exact outgoing initial-field sequence
// with the same reconciliation rules as WithRequestHeaderBlock. Status, body
// framing and hop-by-hop sanitization remain authoritative. It does not change
// ResponseWireHeaderBlocks. Call before returning response from an interceptor;
// configuring a copied/replaced response requires another call.
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

// orderedSendingFields matches individual occurrences, never name groups.
// Structural values are matched by name because they are regenerated from the
// request/response rather than trusted from a potentially stale override.
func orderedSendingFields(fields, order []http.HeaderField, proto int) []http.HeaderField {
	result := make([]http.HeaderField, 0, len(fields))
	used := make([]bool, len(fields))
	appendMatch := func(want http.HeaderField) {
		for i, field := range fields {
			if used[i] || !strings.EqualFold(want.Name, field.Name) || (want.Value != field.Value && !structuralSendingField(field.Name)) {
				continue
			}
			used[i] = true
			if proto == 1 {
				field.Name = want.Name
			} else {
				field.Name = strings.ToLower(field.Name)
				field.Sensitive = want.Sensitive
			}
			result = append(result, field)
			return
		}
	}
	// HTTP/2 requires every pseudo-header before every regular field.
	if proto == 2 {
		for _, field := range order {
			if strings.HasPrefix(field.Name, ":") {
				appendMatch(field)
			}
		}
		for i, field := range fields {
			if !used[i] && strings.HasPrefix(field.Name, ":") {
				used[i] = true
				result = append(result, field)
			}
		}
	}
	for _, field := range order {
		if !strings.HasPrefix(field.Name, ":") {
			appendMatch(field)
		}
	}
	for i, field := range fields {
		if !used[i] {
			result = append(result, field)
		}
	}
	return result
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
	if err == nil && profile.sendHeaderObserver != nil {
		profile.sendHeaderObserver(cloneSendingBlock(block))
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
	return http.HeaderBlock{Kind: http.HeaderBlockInitial, ProtoMajor: proto, StatusCode: status, Fields: orderedSendingFields(fields, profile.writeBlock.Fields, proto)}, true
}

// Response.Write still owns framing; only reorder its fully sanitized head.
func exactHTTP1ResponseHeader(head []byte, response *http.Response) []byte {
	profile, ok := responseWireProfileFor(response)
	if !ok || profile.writeBlock == nil {
		return head
	}
	lines := bytes.Split(head, []byte("\r\n"))
	var fields []http.HeaderField
	for _, line := range lines[1:] {
		name, value, ok := bytes.Cut(line, []byte(":"))
		if ok {
			fields = append(fields, http.HeaderField{Name: string(name), Value: textproto.TrimString(string(value))})
		}
	}
	fields = orderedSendingFields(fields, profile.writeBlock.Fields, 1)
	var output bytes.Buffer
	output.Write(lines[0])
	output.WriteString("\r\n")
	for _, field := range fields {
		output.WriteString(field.Name + ": " + field.Value + "\r\n")
	}
	output.WriteString("\r\n")
	return output.Bytes()
}

func sendingHeaderContains(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// WithHTTPRequestSendHeaderObserver observes the final sanitized header block
// selected by the exact sender during transport preparation, before writing.
// It is not an attempt/completion event. Blocks are caller-owned and include
// the selected upstream protocol. It requires an
// explicit WithRequestHeaderBlock override and never alters received metadata.
func WithHTTPRequestSendHeaderObserver(req *http.Request, observer func(http.HeaderBlock)) *http.Request {
	req = ensureRequestWireProfile(req)
	profile := *requestWireProfileFromRequest(req)
	profile.sendHeaderObserver = observer
	return withRequestWireProfile(req, &profile)
}
func cloneSendingBlock(block http.HeaderBlock) http.HeaderBlock {
	block.Fields = append([]http.HeaderField(nil), block.Fields...)
	return block
}
