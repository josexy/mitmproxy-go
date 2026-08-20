package mitmproxy

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

type trieNode struct {
	children map[string]*trieNode
	isEnd    bool
}

func newTrieNode() *trieNode {
	return &trieNode{}
}

// ErrInvalidHostFilter reports a malformed include or exclude host pattern.
var ErrInvalidHostFilter = errors.New("invalid host filter")

var domainLookupProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.VerifyDNSLength(true))

func buildDomainMatcher(patterns []string) (*trieNode, error) {
	matcher := newTrieNode()
	for i, pattern := range patterns {
		if err := matcher.insert(pattern); err != nil {
			return nil, fmt.Errorf("host filter at index %d: %w", i, err)
		}
	}
	return matcher, nil
}

func (node *trieNode) insert(pattern string) error {
	normalized, err := canonicalizeDomainPattern(pattern)
	if err != nil {
		return fmt.Errorf("%w %q: %v", ErrInvalidHostFilter, pattern, err)
	}
	parts := strings.Split(normalized, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.children == nil {
			node.children = make(map[string]*trieNode)
		}
		if node.children[part] == nil {
			node.children[part] = &trieNode{}
		}
		node = node.children[part]
	}

	node.isEnd = true
	return nil
}

func (node *trieNode) match(domain string) bool {
	normalized, err := canonicalizeDomainHost(domain)
	if err != nil {
		return false
	}
	return node.matchSuffix(normalized, len(normalized))
}

func normalizeDomain(domain string) string {
	if normalized, err := canonicalizeDomainHost(domain); err == nil {
		return normalized
	}
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimRight(domain, ".")
}

func canonicalizeDomainPattern(pattern string) (string, error) {
	pattern = normalizeIDNASeparators(strings.TrimSpace(pattern))
	if !strings.ContainsRune(pattern, '*') {
		return canonicalizeDomainHost(pattern)
	}
	pattern, err := trimRootDot(pattern)
	if err != nil {
		return "", err
	}
	if strings.ContainsRune(pattern, ':') || strings.ContainsAny(pattern, "[]") {
		return "", errors.New("wildcards are not valid in IP address patterns")
	}

	parts := strings.Split(pattern, ".")
	for i, part := range parts {
		switch {
		case part == "*":
			continue
		case strings.ContainsRune(part, '*'):
			return "", errors.New("wildcard must occupy an entire label")
		default:
			normalized, err := canonicalizeDomainLabel(part)
			if err != nil {
				return "", err
			}
			parts[i] = normalized
		}
	}
	normalized := strings.Join(parts, ".")
	if len(normalized) > 253 {
		return "", errors.New("domain name exceeds 253 bytes")
	}
	return normalized, nil
}

func canonicalizeDomainHost(domain string) (string, error) {
	domain = normalizeIDNASeparators(strings.TrimSpace(domain))
	if domain == "" {
		return "", errors.New("host is empty")
	}
	if strings.HasPrefix(domain, "[") || strings.HasSuffix(domain, "]") {
		if !strings.HasPrefix(domain, "[") || !strings.HasSuffix(domain, "]") {
			return "", errors.New("invalid bracketed IP address")
		}
		addr, err := netip.ParseAddr(domain[1 : len(domain)-1])
		if err != nil {
			return "", fmt.Errorf("invalid bracketed IP address: %w", err)
		}
		return addr.String(), nil
	}
	if looksLikeIPAddress(domain) {
		if addr, err := netip.ParseAddr(domain); err == nil {
			return addr.String(), nil
		}
	}
	if strings.ContainsRune(domain, ':') {
		return "", errors.New("host must not contain a port")
	}

	domain, err := trimRootDot(domain)
	if err != nil {
		return "", err
	}
	if isASCII(domain) {
		domain = strings.ToLower(domain)
		if err := validateASCIIDomain(domain); err != nil {
			return "", err
		}
		return domain, nil
	}

	domain, err = domainLookupProfile.ToASCII(domain)
	if err != nil {
		return "", fmt.Errorf("invalid IDN: %w", err)
	}
	domain = strings.ToLower(domain)
	if err := validateASCIIDomain(domain); err != nil {
		return "", err
	}
	return domain, nil
}

func canonicalizeDomainLabel(label string) (string, error) {
	if label == "" {
		return "", errors.New("domain contains an empty label")
	}
	if isASCII(label) {
		label = strings.ToLower(label)
	} else {
		var err error
		label, err = domainLookupProfile.ToASCII(label)
		if err != nil {
			return "", fmt.Errorf("invalid IDN label: %w", err)
		}
		label = strings.ToLower(label)
	}
	if err := validateASCIILabel(label); err != nil {
		return "", err
	}
	return label, nil
}

func trimRootDot(domain string) (string, error) {
	if strings.HasSuffix(domain, ".") {
		domain = domain[:len(domain)-1]
	}
	if domain == "" {
		return "", errors.New("host is empty")
	}
	return domain, nil
}

func normalizeIDNASeparators(domain string) string {
	if !strings.ContainsAny(domain, "\u3002\uff0e\uff61") {
		return domain
	}
	return strings.Map(func(r rune) rune {
		switch r {
		case '\u3002', '\uff0e', '\uff61':
			return '.'
		default:
			return r
		}
	}, domain)
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}

func looksLikeIPAddress(host string) bool {
	if strings.ContainsRune(host, ':') {
		return true
	}
	hasDot := false
	for i := 0; i < len(host); i++ {
		switch {
		case host[i] == '.':
			hasDot = true
		case host[i] >= '0' && host[i] <= '9':
		default:
			return false
		}
	}
	return hasDot
}

func validateASCIIDomain(domain string) error {
	if len(domain) > 253 {
		return errors.New("domain name exceeds 253 bytes")
	}
	labelStart := 0
	for i := 0; i <= len(domain); i++ {
		if i < len(domain) && domain[i] != '.' {
			continue
		}
		if err := validateASCIILabel(domain[labelStart:i]); err != nil {
			return err
		}
		labelStart = i + 1
	}
	return nil
}

func validateASCIILabel(label string) error {
	if label == "" {
		return errors.New("domain contains an empty label")
	}
	if len(label) > 63 {
		return errors.New("domain label exceeds 63 bytes")
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return errors.New("domain label must not start or end with a hyphen")
	}
	for i := 0; i < len(label); i++ {
		ch := label[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
			continue
		}
		return fmt.Errorf("invalid domain label character %q", ch)
	}
	return nil
}

func (node *trieNode) matchSuffix(domain string, end int) bool {
	if end < 0 {
		return node.isEnd
	}

	start := strings.LastIndexByte(domain[:end], '.')
	part := domain[start+1 : end]
	if child, exists := node.children[part]; exists {
		if child.matchSuffix(domain, start) {
			return true
		}
	}
	if wildcardChild, exists := node.children["*"]; exists {
		if wildcardChild.matchWildcardSuffix(domain, start) {
			return true
		}
	}
	return false
}

// matchWildcardSuffix continues matching after a wildcard has consumed at
// least one label. At each remaining label boundary, the wildcard may either
// stop and match its child nodes or consume one more complete label.
func (node *trieNode) matchWildcardSuffix(domain string, end int) bool {
	if node.matchSuffix(domain, end) {
		return true
	}
	if end < 0 {
		return false
	}
	start := strings.LastIndexByte(domain[:end], '.')
	return node.matchWildcardSuffix(domain, start)
}
