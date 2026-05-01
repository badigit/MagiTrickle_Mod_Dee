package trie

import (
	"strings"
	"sync"
)

// TrieNode represents a node in the Trie.
// Each node holds independent slots for an exact-match entry and a namespace-match
// entry, so two rules with the same domain string but different semantics coexist
// instead of overwriting each other.
type TrieNode struct {
	children map[string]*TrieNode

	isExactEnd bool
	exactData  interface{}

	isNamespaceEnd bool
	namespaceData  interface{}
}

// Trie is a thread-safe prefix tree for domain matching
type Trie struct {
	root *TrieNode
	mu   sync.RWMutex
}

// New creates a new Trie
func New() *Trie {
	return &Trie{
		root: &TrieNode{
			children: make(map[string]*TrieNode),
		},
	}
}

// Insert adds a domain to the Trie with associated data.
// Domains are stored in reverse part order: "google.com" -> "com" -> "google".
// exact: if true, this rule will NOT match subdomains (strict domain match).
//
// First insert wins per slot (exact / namespace) — matches iptables chain priority,
// so the routing decision in trie agrees with which iptables chain handles the packet.
func (t *Trie) Insert(domain string, data interface{}, exact bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parts := strings.Split(domain, ".")
	node := t.root

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.children[part] == nil {
			node.children[part] = &TrieNode{
				children: make(map[string]*TrieNode),
			}
		}
		node = node.children[part]
	}

	if exact {
		if !node.isExactEnd {
			node.isExactEnd = true
			node.exactData = data
		}
	} else {
		if !node.isNamespaceEnd {
			node.isNamespaceEnd = true
			node.namespaceData = data
		}
	}
}

// Search looks up a domain in the Trie.
// Returns the data associated with the longest matching suffix; exact match on the
// leaf wins over a namespace match on the same node.
func (t *Trie) Search(domain string) (interface{}, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := strings.Split(domain, ".")
	node := t.root

	var lastMatchData interface{}
	var found bool

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		nextNode, ok := node.children[part]
		if !ok {
			return lastMatchData, found
		}
		node = nextNode

		if node.isNamespaceEnd {
			lastMatchData = node.namespaceData
			found = true
		}
		if i == 0 && node.isExactEnd {
			return node.exactData, true
		}
	}

	return lastMatchData, found
}
