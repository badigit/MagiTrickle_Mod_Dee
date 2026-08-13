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
// Kind* describe which layer of the trie produced a match. They exist so callers
// can explain a routing decision (see /api/v1/lookup winner), not just act on it.
const (
	KindExact     = "exact"
	KindNamespace = "namespace"
)

// Search returns the data for the closest matching rule, if any.
// It is a thin wrapper over SearchExplain: keeping one implementation guarantees
// that an explanation shown to the user can never disagree with the routing
// decision actually taken.
func (t *Trie) Search(domain string) (interface{}, bool) {
	data, _, found := t.SearchExplain(domain)
	return data, found
}

// SearchExplain is Search plus the layer that matched: KindExact when a strict
// domain rule matched the query itself, KindNamespace when a parent namespace
// rule caught it. On a miss kind is empty.
func (t *Trie) SearchExplain(domain string) (interface{}, string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	parts := strings.Split(domain, ".")
	node := t.root

	var lastMatchData interface{}
	var lastKind string
	var found bool

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]

		nextNode, ok := node.children[part]
		if !ok {
			return lastMatchData, lastKind, found
		}
		node = nextNode

		if node.isNamespaceEnd {
			lastMatchData = node.namespaceData
			lastKind = KindNamespace
			found = true
		}
		if i == 0 && node.isExactEnd {
			return node.exactData, KindExact, true
		}
	}

	return lastMatchData, lastKind, found
}
