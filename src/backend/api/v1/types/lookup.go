package types

type LookupReq struct {
	Queries    []string `json:"queries"`
	CheckIpset bool     `json:"check_ipset"`
}

type LookupRes struct {
	Results []LookupResult `json:"results"`
}

type LookupResult struct {
	Query      string        `json:"query"`
	RuleHits   []RuleHit     `json:"rule_hits"`
	IpsetHits  []IpsetHit    `json:"ipset_hits,omitempty"`
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
