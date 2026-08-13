package types

type LookupReq struct {
	Queries    []string `json:"queries"`
	CheckIpset bool     `json:"check_ipset"`
}

type LookupRes struct {
	Results []LookupResult `json:"results"`
}

type LookupResult struct {
	Query string `json:"query"`
	// Winner — кто реально выигрывает запрос. Отсутствует, когда не выигрывает
	// никто. RuleHits рядом намеренно: winner отвечает «что будет», список
	// совпадений — «почему», и порознь они бесполезны при разборе конфликта.
	Winner    *LookupWinner `json:"winner,omitempty"`
	RuleHits  []RuleHit     `json:"rule_hits"`
	IpsetHits []IpsetHit    `json:"ipset_hits,omitempty"`
}

// LookupWinner — исход арбитража по тем же правилам, что применяет роутинг:
// для домена — searchDomain (trie exact/namespace > wildcard > regex, при
// равном слое выигрывает первая группа), для IP — первая группа, в чьём ipset
// адрес уже лежит.
type LookupWinner struct {
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
	Source    string `json:"source"` // "group" or "subscription"
	// Why — models.LookupWhy*: exact, namespace, wildcard, regex, ipset-first, subnet.
	Why string `json:"why"`
	// Pending — правило совпало, но в ipset адреса ещё нет: победитель назван
	// верно, однако прямо сейчас трафик пойдёт мимо него (домен ещё не
	// резолвился через MagiTrickle либо sync не прошёл).
	Pending bool `json:"pending,omitempty"`
}

type RuleHit struct {
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
	Source    string `json:"source"` // "group" or "subscription"
	RuleType  string `json:"rule_type"`
	Rule      string `json:"rule"`
	Match     string `json:"match"` // "exact", "namespace", "wildcard", "contains", "subnet_of", "supernet_of"
}

type IpsetHit struct {
	GroupID   string `json:"group_id"`
	GroupName string `json:"group_name"`
	Source    string `json:"source"`
}
