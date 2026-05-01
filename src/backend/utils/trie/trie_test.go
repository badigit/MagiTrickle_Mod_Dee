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

// TestFirstInsertWins фиксирует приоритет порядка групп в конфиге:
// при коллизии одинаковых правил между группами выигрывает первая.
func TestFirstInsertWins(t *testing.T) {
	tr := New()
	tr.Insert("google.com", "groupA", true)
	tr.Insert("google.com", "groupB", true) // должен быть проигнорирован

	data, ok := tr.Search("google.com")
	if !ok || data != "groupA" {
		t.Fatalf("first insert should win, got %v", data)
	}
}

// TestExactNamespaceCoexist фиксирует, что exact и namespace на одну и ту же
// строку сосуществуют: на самом домене побеждает exact, на поддомене — namespace.
func TestExactNamespaceCoexist(t *testing.T) {
	tr := New()
	tr.Insert("google.com", "EXACT", true)
	tr.Insert("google.com", "NS", false)

	if data, ok := tr.Search("google.com"); !ok || data != "EXACT" {
		t.Fatalf("exact should win on the leaf, got %v ok=%v", data, ok)
	}
	if data, ok := tr.Search("mail.google.com"); !ok || data != "NS" {
		t.Fatalf("namespace should match subdomain, got %v ok=%v", data, ok)
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

// BenchmarkTrieMixed — exact и namespace на одних и тех же доменных строках
// (горячий сценарий, ради которого узел теперь хранит два слота).
func BenchmarkTrieMixed(b *testing.B) {
	tr := New()
	tlds := []string{"com", "ru", "org", "net", "io"}
	for i := 0; i < 2000; i++ {
		d := "service" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + "." + tlds[i%len(tlds)]
		tr.Insert(d, i, true)  // exact
		tr.Insert(d, i, false) // namespace на ту же строку
	}
	hit := "sub.servicea0.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tr.Search(hit)
	}
}

// BenchmarkTrieVsLinear — сравнение trie vs линейный перебор на 4000 правилах
func BenchmarkTrieVsLinear(b *testing.B) {
	type rule struct {
		domain string
		exact  bool
	}

	// Генерируем 4000 правил — реалистичные домены
	rules := make([]rule, 4000)
	tlds := []string{"com", "ru", "org", "net", "io"}
	for i := 0; i < 4000; i++ {
		tld := tlds[i%len(tlds)]
		rules[i] = rule{
			domain: "service" + string(rune('a'+i%26)) + string(rune('0'+i%10)) + "." + tld,
			exact:  i%3 != 0, // 2/3 exact, 1/3 namespace
		}
	}

	// Домен для поиска — worst case (не найден)
	searchMiss := "nonexistent.example.com"
	// Домен для поиска — hit (последнее правило)
	searchHit := "sub." + rules[3999].domain

	// Trie setup
	tr := New()
	for _, r := range rules {
		tr.Insert(r.domain, r.domain, r.exact)
	}

	b.Run("Trie_Hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr.Search(searchHit)
		}
	})

	b.Run("Trie_Miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			tr.Search(searchMiss)
		}
	})

	b.Run("Linear_Hit", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, r := range rules {
				if r.exact {
					if searchHit == r.domain {
						break
					}
				} else {
					if searchHit == r.domain {
						break
					}
					rLen := len(r.domain)
					sLen := len(searchHit)
					if sLen > rLen+1 && searchHit[sLen-rLen-1] == '.' && searchHit[sLen-rLen:] == r.domain {
						break
					}
				}
			}
		}
	})

	b.Run("Linear_Miss", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, r := range rules {
				if r.exact {
					if searchMiss == r.domain {
						break
					}
				} else {
					if searchMiss == r.domain {
						break
					}
					rLen := len(r.domain)
					sLen := len(searchMiss)
					if sLen > rLen+1 && searchMiss[sLen-rLen-1] == '.' && searchMiss[sLen-rLen:] == r.domain {
						break
					}
				}
			}
		}
	})
}
