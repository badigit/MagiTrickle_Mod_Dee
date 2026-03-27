package trie

import "testing"

func TestExactMatch(t *testing.T) {
	tr := New()
	tr.Insert("google.com", "g", true)

	if _, ok := tr.Search("google.com"); !ok {
		t.Fatal("exact match should find google.com")
	}
	if _, ok := tr.Search("mail.google.com"); ok {
		t.Fatal("exact match should NOT find mail.google.com")
	}
}

func TestNamespaceMatch(t *testing.T) {
	tr := New()
	tr.Insert("google.com", "g", false)

	if _, ok := tr.Search("google.com"); !ok {
		t.Fatal("namespace should match google.com itself")
	}
	if _, ok := tr.Search("mail.google.com"); !ok {
		t.Fatal("namespace should match mail.google.com")
	}
	if _, ok := tr.Search("deep.mail.google.com"); !ok {
		t.Fatal("namespace should match deep.mail.google.com")
	}
	if _, ok := tr.Search("yahoo.com"); ok {
		t.Fatal("namespace should NOT match yahoo.com")
	}
}

func TestLongestMatch(t *testing.T) {
	tr := New()
	tr.Insert("com", "tld", false)
	tr.Insert("google.com", "google", false)

	data, ok := tr.Search("mail.google.com")
	if !ok || data != "google" {
		t.Fatalf("should match google.com (longest), got %v %v", data, ok)
	}

	data, ok = tr.Search("yahoo.com")
	if !ok || data != "tld" {
		t.Fatalf("should match com, got %v %v", data, ok)
	}
}

func BenchmarkTrieSearch(b *testing.B) {
	tr := New()
	for i := 0; i < 4000; i++ {
		tr.Insert("domain"+string(rune('A'+i%26))+".example.com", i, false)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Search("sub.domainA.example.com")
	}
}
