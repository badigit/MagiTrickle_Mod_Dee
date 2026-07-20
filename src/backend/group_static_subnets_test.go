package magitrickle

import (
	"reflect"
	"testing"

	"magitrickle/models"
	"magitrickle/utils/netfilterTools"
)

// TestStaticSubnetsFromRules проверяет парсер статических subnet-правил,
// вынесенный из group.sync (используется и в ReassertStaticSubnets):
// одиночный IP → /32, CIDR как есть, 0.0.0.0/0 → split на две /1 (netlink-баг),
// выключенные/мусорные/доменные правила игнорируются.
func TestStaticSubnetsFromRules(t *testing.T) {
	rules := []*models.Rule{
		{Type: models.RuleTypeSubnet, Rule: "1.2.3.4", Enable: true},
		{Type: models.RuleTypeSubnet, Rule: "10.0.0.0/8", Enable: true},
		{Type: models.RuleTypeSubnet, Rule: "0.0.0.0/0", Enable: true},
		{Type: models.RuleTypeSubnet, Rule: "5.6.7.8", Enable: false},    // выключено
		{Type: models.RuleTypeSubnet, Rule: "not-an-ip", Enable: true},   // мусор
		{Type: models.RuleTypeDomain, Rule: "example.com", Enable: true}, // не subnet
		{Type: models.RuleTypeSubnet6, Rule: "2001:db8::1", Enable: true},
		{Type: models.RuleTypeSubnet6, Rule: "2001:db8::/32", Enable: true},
	}

	v4, v6 := staticSubnetsFromRules(rules)

	wantV4 := []netfilterTools.IPv4Subnet{
		{Address: [4]byte{1, 2, 3, 4}, CIDR: 32},
		{Address: [4]byte{10, 0, 0, 0}, CIDR: 8},
		{Address: [4]byte{0x00}, CIDR: 1}, // 0.0.0.0/0 → две /1
		{Address: [4]byte{0x80}, CIDR: 1},
	}
	if !reflect.DeepEqual(v4, wantV4) {
		t.Errorf("v4 mismatch.\nWant: %v\nGot:  %v", wantV4, v4)
	}

	if len(v6) != 2 {
		t.Fatalf("v6 len = %d, want 2", len(v6))
	}
	if v6[0].CIDR != 128 {
		t.Errorf("single IPv6 CIDR = %d, want 128", v6[0].CIDR)
	}
	if v6[1].CIDR != 32 {
		t.Errorf("IPv6 /32 CIDR = %d, want 32", v6[1].CIDR)
	}
}

// TestUpdateStaticHostCache: в кэш host-членов попадают ТОЛЬКО одиночные
// IP (/32, /128) — широкие подсети и dirty-hack /1 не попадают (у них другой
// ipset-member, DNS-add их не клобберит).
func TestUpdateStaticHostCache(t *testing.T) {
	rules := []*models.Rule{
		{Type: models.RuleTypeSubnet, Rule: "1.2.3.4", Enable: true},
		{Type: models.RuleTypeSubnet, Rule: "10.0.0.0/8", Enable: true},
		{Type: models.RuleTypeSubnet, Rule: "0.0.0.0/0", Enable: true},
		{Type: models.RuleTypeSubnet6, Rule: "2001:db8::1", Enable: true},
		{Type: models.RuleTypeSubnet6, Rule: "2001:db8::/32", Enable: true},
	}
	g := &Group{Group: &models.Group{Enable: true, Rules: rules}}

	v4, v6 := staticSubnetsFromRules(g.Rules)
	g.updateStaticHostCache(v4, v6)

	if _, ok := g.staticHostV4[[4]byte{1, 2, 3, 4}]; !ok {
		t.Error("single IPv4 1.2.3.4 must be in host cache")
	}
	if _, ok := g.staticHostV4[[4]byte{10, 0, 0, 0}]; ok {
		t.Error("/8 subnet base must NOT be in host cache")
	}
	if _, ok := g.staticHostV4[[4]byte{0x00}]; ok {
		t.Error("dirty-hack /1 must NOT be in host cache")
	}
	wantV6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if _, ok := g.staticHostV6[wantV6]; !ok {
		t.Error("single IPv6 2001:db8::1 must be in host cache")
	}
	if len(g.staticHostV6) != 1 {
		t.Errorf("staticHostV6 len = %d, want 1 (broad /32 excluded)", len(g.staticHostV6))
	}
}

// TestAddSubnetGuardsStaticHost — ключевой регресс на DNS-клоббер (близнец
// апстримного 'TODO: Check already existed'): TTL'ный AddIPv4Subnet на IP
// статического host-правила должен скипнуться ДО обращения к ipset. Группа
// собрана с g.ipset == nil: если guard не сработает и вызов дойдёт до
// netlink-обёртки — тест упадёт паникой на nil-указателе.
func TestAddSubnetGuardsStaticHost(t *testing.T) {
	g := &Group{Group: &models.Group{Enable: true, Rules: []*models.Rule{
		{Type: models.RuleTypeSubnet, Rule: "1.2.3.4", Enable: true},
		{Type: models.RuleTypeSubnet6, Rule: "2001:db8::1", Enable: true},
	}}}
	g.enabled.Store(true)
	v4, v6 := staticSubnetsFromRules(g.Rules)
	g.updateStaticHostCache(v4, v6)

	ttl := uint32(3600)

	// DNS-путь добавляет host как CIDR 0 — guard должен матчить и эту форму.
	if err := g.AddIPv4Subnet(netfilterTools.IPv4Subnet{Address: [4]byte{1, 2, 3, 4}}, &ttl); err != nil {
		t.Errorf("guarded v4 add (CIDR 0) must be skipped silently, got: %v", err)
	}
	if err := g.AddIPv4Subnet(netfilterTools.IPv4Subnet{Address: [4]byte{1, 2, 3, 4}, CIDR: 32}, &ttl); err != nil {
		t.Errorf("guarded v4 add (CIDR 32) must be skipped silently, got: %v", err)
	}
	addr6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	if err := g.AddIPv6Subnet(netfilterTools.IPv6Subnet{Address: addr6}, &ttl); err != nil {
		t.Errorf("guarded v6 add must be skipped silently, got: %v", err)
	}
}
