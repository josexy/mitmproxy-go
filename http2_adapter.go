package mitmproxy

import (
	"fmt"
	"runtime"
	"strings"
	"weak"

	nethttp2 "github.com/josexy/net/http2"
	http "github.com/josexy/xhttp"
)

func prepareHTTP2Request(req *http.Request) (*http.Request, error) {
	preparedReq := req.Clone(req.Context())
	preparedReq.RequestURI = ""
	// Request trailers are populated as the shared streaming body reaches EOF.
	preparedReq.Trailer = req.Trailer
	profile := requestWireProfileFromRequest(req)

	order := requestHeaderOrder(req)
	netOrder := nethttp2.HeaderOrder{
		Headers:  order.Headers,
		Trailers: order.Trailers,
	}
	if profile != nil && profile.fingerprint == nil {
		pseudos := make([]string, 0, len(profile.headerOrder))
		for _, name := range profile.headerOrder {
			if strings.HasPrefix(name, ":") {
				pseudos = append(pseudos, name)
			}
		}
		netOrder.Headers = append(pseudos, netOrder.Headers...)
	}
	var err error
	if len(netOrder.Headers) > 0 || len(netOrder.Trailers) > 0 {
		preparedReq, err = nethttp2.WithRequestHeaderOrder(preparedReq, netOrder)
		if err != nil {
			return nil, fmt.Errorf("apply HTTP/2 header order: %w", err)
		}
	}

	if profile != nil && profile.fingerprint != nil {
		converted := convertHTTP2Fingerprint(*profile.fingerprint)
		converted.PseudoHeaderOrder = compatiblePseudoHeaderOrder(preparedReq, converted.PseudoHeaderOrder)
		preparedReq, err = nethttp2.WithRequestFingerprint(preparedReq, converted)
		if err != nil {
			return nil, fmt.Errorf("apply HTTP/2 fingerprint: %w", err)
		}
	}
	return preparedReq, nil
}

func convertHTTP2Fingerprint(source http.Fingerprint) nethttp2.Fingerprint {
	converted := nethttp2.Fingerprint{
		WindowUpdate:      source.WindowUpdate,
		PseudoHeaderOrder: append([]string(nil), source.PseudoHeaderOrder...),
	}
	if source.Settings != nil {
		converted.Settings = make([]nethttp2.Setting, len(source.Settings))
	}
	for i, setting := range source.Settings {
		converted.Settings[i] = nethttp2.Setting{
			ID:  nethttp2.SettingID(setting.ID),
			Val: setting.Val,
		}
	}
	if source.Priorities != nil {
		converted.Priorities = make([]nethttp2.FingerprintPriority, len(source.Priorities))
	}
	for i, priority := range source.Priorities {
		converted.Priorities[i] = nethttp2.FingerprintPriority{
			StreamID:  priority.StreamID,
			StreamDep: priority.StreamDep,
			Exclusive: priority.Exclusive,
			Weight:    priority.Weight,
		}
	}
	if source.HeaderPriority != nil {
		converted.HeaderPriority = &nethttp2.FingerprintHeaderPriority{
			StreamDep: source.HeaderPriority.StreamDep,
			Exclusive: source.HeaderPriority.Exclusive,
			Weight:    source.HeaderPriority.Weight,
		}
	}
	return converted
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
		blocks := convertHTTP2ResponseHeaderBlocks(nethttp2.ResponseHeaderBlocks(response))
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

func convertHTTP2ResponseHeaderBlocks(source []nethttp2.HeaderBlock) []http.HeaderBlock {
	if len(source) == 0 {
		return nil
	}
	converted := make([]http.HeaderBlock, len(source))
	for i, block := range source {
		converted[i] = http.HeaderBlock{
			Kind:       http.HeaderBlockKind(block.Kind),
			Truncated:  block.Truncated,
			ProtoMajor: 2,
			Fields:     make([]http.HeaderField, len(block.Fields)),
		}
		for j, field := range block.Fields {
			converted[i].Fields[j] = http.HeaderField{
				Name:      field.Name,
				Value:     field.Value,
				Sensitive: field.Sensitive,
			}
		}
	}
	return converted
}
