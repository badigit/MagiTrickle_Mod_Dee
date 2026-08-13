package trie

import "testing"

// SearchExplain нужен объяснению исхода в /api/v1/lookup: Search говорит ТОЛЬКО
// «нашлось», а пользователю в конфликте правил важно, каким слоем он выигран —
// точным правилом или родительским namespace. Данные обоих методов обязаны
// совпадать, иначе объяснение начнёт расходиться с реальным роутингом.
func TestSearchExplainKind(t *testing.T) {
	cases := []struct {
		name      string
		insert    func(*Trie)
		query     string
		wantData  string
		wantKind  string
		wantFound bool
	}{
		{
			name:      "точное правило",
			insert:    func(tr *Trie) { tr.Insert("example.com", "exactGroup", true) },
			query:     "example.com",
			wantData:  "exactGroup",
			wantKind:  KindExact,
			wantFound: true,
		},
		{
			name:      "namespace ловит поддомен",
			insert:    func(tr *Trie) { tr.Insert("example.com", "nsGroup", false) },
			query:     "cdn.example.com",
			wantData:  "nsGroup",
			wantKind:  KindNamespace,
			wantFound: true,
		},
		{
			name: "точное бьёт namespace на самом домене",
			insert: func(tr *Trie) {
				tr.Insert("example.com", "nsGroup", false)
				tr.Insert("example.com", "exactGroup", true)
			},
			query:     "example.com",
			wantData:  "exactGroup",
			wantKind:  KindExact,
			wantFound: true,
		},
		{
			name:      "точное правило не ловит поддомен",
			insert:    func(tr *Trie) { tr.Insert("example.com", "exactGroup", true) },
			query:     "cdn.example.com",
			wantKind:  "",
			wantFound: false,
		},
		{
			name:      "промах",
			insert:    func(tr *Trie) { tr.Insert("example.com", "exactGroup", true) },
			query:     "example.org",
			wantKind:  "",
			wantFound: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := New()
			tc.insert(tr)

			data, kind, found := tr.SearchExplain(tc.query)
			if found != tc.wantFound {
				t.Fatalf("found = %v, want %v", found, tc.wantFound)
			}
			if kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", kind, tc.wantKind)
			}
			if tc.wantFound {
				if s, _ := data.(string); s != tc.wantData {
					t.Errorf("data = %v, want %v", data, tc.wantData)
				}
			}

			// Паритет: Search обязан отдавать ровно то же решение.
			sData, sFound := tr.Search(tc.query)
			if sFound != found {
				t.Errorf("паритет found: Search = %v, SearchExplain = %v", sFound, found)
			}
			if sFound && sData != data {
				t.Errorf("паритет data: Search = %v, SearchExplain = %v", sData, data)
			}
		})
	}
}
