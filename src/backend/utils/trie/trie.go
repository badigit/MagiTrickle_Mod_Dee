package trie

import (
	"strings"
	"sync"
)

// TrieNode represents a node in the Trie
type TrieNode struct {
	children map[string]*TrieNode
	// data holds the arbitrary data associated with the domain (e.g., pointer to Group)
	data    interface{}
	isEnd   bool
	isExact bool // true = Domain, false = Namespace
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
// Domains are stored in reverse part order: "google.com" -> "com" -> "google"
// exact: if true, this rule will NOT match subdomains (strict domain match).
func (t *Trie) Insert(domain string, data interface{}, exact bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	parts := strings.Split(domain, ".")
	node := t.root

	// Insert in reverse order
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.children[part] == nil {
			node.children[part] = &TrieNode{
				children: make(map[string]*TrieNode),
			}
		}
		node = node.children[part]
	}
	node.isEnd = true
	node.isExact = exact
	node.data = data
}

// Search looks up a domain in the Trie.
// Returns the data associated with the longest matching suffix (or exact match).
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

		if node.isEnd {
			if node.isExact {
				if i == 0 {
					return node.data, true
				}
			} else {
				lastMatchData = node.data
				found = true
			}
		}
	}

	return lastMatchData, found
}
