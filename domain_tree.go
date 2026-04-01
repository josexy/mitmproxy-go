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
	pattern = strings.ToLower(strings.TrimSpace(pattern))
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
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	parts := strings.Split(domain, ".")
	return node.dfsMatch(parts, len(parts)-1)
}

func (node *trieNode) dfsMatch(parts []string, index int) bool {
	if index < 0 {
		return node.isEnd
	}
	part := parts[index]
	if child, exists := node.children[part]; exists {
		if child.dfsMatch(parts, index-1) {
			return true
		}
	}
	if wildcardChild, exists := node.children["*"]; exists {
		if wildcardChild.dfsMatch(parts, index-1) {
			return true
		}
	}
	return false
}
