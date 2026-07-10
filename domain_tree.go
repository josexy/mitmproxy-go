package mitmproxy

import (
	"strings"
)

type trieNode struct {
	children   map[string]*trieNode
	isWildcard bool
	isEnd      bool
}

func newTrieNode() *trieNode {
	return &trieNode{
		children: make(map[string]*trieNode),
	}
}

func (node *trieNode) insert(pattern string) {
	pattern = normalizeDomain(pattern)
	if pattern == "" {
		return
	}
	parts := strings.Split(pattern, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.children[part] == nil {
			node.children[part] = &trieNode{
				children: make(map[string]*trieNode),
			}
		}
		node = node.children[part]
		if part == "*" {
			node.isWildcard = true
		}
	}

	node.isEnd = true
}

func (node *trieNode) match(domain string) bool {
	domain = normalizeDomain(domain)
	if domain == "" {
		return false
	}
	return node.matchSuffix(domain, len(domain))
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return strings.TrimRight(domain, ".")
}

func (node *trieNode) matchSuffix(domain string, end int) bool {
	if end <= 0 {
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
		if wildcardChild.matchSuffix(domain, start) {
			return true
		}
	}
	return false
}
