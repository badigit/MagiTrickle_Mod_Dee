package magitrickle

import (
	"net"
	"testing"
	"time"

	"magitrickle/models"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"
)

// TestDesiredSubnetsHostKeysCanonical — регресс mt-bku: ядро в hash:net при
// листинге ВСЕГДА отдаёт IPSET_ATTR_CIDR (hash_net4_data_list, безусловный
// nla_put_u8 — одинаково в v3.10 и master), поэтому host-записи приходят из
// listIPv4/IPv6Subnets с CIDR=32/128 — даже если добавлялись с CIDR=0
// (проверено пробником на реальном ядре). Если desiredSubnets кладёт
// DNS-производные записи с ключом CIDR=0, ключ не совпадает со старым списком:
// add-цикл sync переливает запись заново (безвредно), а delete-цикл удаляет
// {addr, 32} — ту же самую kernel-запись. До фикса каждый sync() (SyncAllGroups
// на любом изменении конфига) сносил все DNS /32 и /128 из сета до следующего
// резолва — трафик к ним временно уходил direct. Ключи host-записей ОБЯЗАНЫ
// быть в форме ядра: явные /32 и /128.
func TestDesiredSubnetsHostKeysCanonical(t *testing.T) {
	app := &App{}
	app.recordsCache = recordsCache.New()
	app.recordsCache.AddAddress("example.com", net.ParseIP("1.2.3.4").To4(), 3600)
	app.recordsCache.AddAddress("example.com", net.ParseIP("2001:db8::1").To16(), 3600)

	g := &Group{
		Group: &models.Group{Enable: true, Rules: []*models.Rule{
			{Type: models.RuleTypeDomain, Rule: "example.com", Enable: true},
			{Type: models.RuleTypeSubnet, Rule: "5.6.7.8", Enable: true},
			{Type: models.RuleTypeSubnet, Rule: "10.0.0.0/8", Enable: true},
		}},
		app: app,
	}

	v4, v6 := g.desiredSubnets(time.Now())

	// DNS-производный IPv4 — канонический /32 с TTL.
	wantV4 := netfilterTools.IPv4Subnet{Address: [4]byte{1, 2, 3, 4}, CIDR: 32}
	if ttl, ok := v4[wantV4]; !ok {
		t.Errorf("v4 must contain canonical /32 key %v (форма листинга ядра), got: %v", wantV4, v4)
	} else if ttl == nil {
		t.Errorf("DNS-derived v4 entry must carry TTL, got nil (permanent)")
	}
	// Ключей с CIDR=0 быть не должно вовсе — они не совпадут с листингом ядра.
	for subnet := range v4 {
		if subnet.CIDR == 0 {
			t.Errorf("v4 contains non-canonical CIDR=0 key %v — delete-цикл sync снесёт живую /32", subnet)
		}
	}

	// DNS-производный IPv6 — канонический /128 с TTL.
	addr6 := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	wantV6 := netfilterTools.IPv6Subnet{Address: addr6, CIDR: 128}
	if ttl, ok := v6[wantV6]; !ok {
		t.Errorf("v6 must contain canonical /128 key %v (форма листинга ядра), got: %v", wantV6, v6)
	} else if ttl == nil {
		t.Errorf("DNS-derived v6 entry must carry TTL, got nil (permanent)")
	}
	for subnet := range v6 {
		if subnet.CIDR == 0 {
			t.Errorf("v6 contains non-canonical CIDR=0 key %v — delete-цикл sync снесёт живую /128", subnet)
		}
	}

	// Статические записи не меняются: одиночный IP — /32 permanent, подсеть как есть.
	staticHost := netfilterTools.IPv4Subnet{Address: [4]byte{5, 6, 7, 8}, CIDR: 32}
	if ttl, ok := v4[staticHost]; !ok {
		t.Errorf("v4 must contain static host %v", staticHost)
	} else if ttl != nil {
		t.Errorf("static host entry must be permanent (nil TTL), got %v", *ttl)
	}
	staticNet := netfilterTools.IPv4Subnet{Address: [4]byte{10, 0, 0, 0}, CIDR: 8}
	if _, ok := v4[staticNet]; !ok {
		t.Errorf("v4 must contain static subnet %v", staticNet)
	}
}

// TestDesiredSubnetsStaticWinsOverDNS — статическая host-запись (permanent)
// не должна затираться DNS-производным TTL для того же IP: в целевом состоянии
// остаётся nil (permanent).
func TestDesiredSubnetsStaticWinsOverDNS(t *testing.T) {
	app := &App{}
	app.recordsCache = recordsCache.New()
	app.recordsCache.AddAddress("example.com", net.ParseIP("5.6.7.8").To4(), 3600)

	g := &Group{
		Group: &models.Group{Enable: true, Rules: []*models.Rule{
			{Type: models.RuleTypeDomain, Rule: "example.com", Enable: true},
			{Type: models.RuleTypeSubnet, Rule: "5.6.7.8", Enable: true},
		}},
		app: app,
	}

	v4, _ := g.desiredSubnets(time.Now())

	key := netfilterTools.IPv4Subnet{Address: [4]byte{5, 6, 7, 8}, CIDR: 32}
	ttl, ok := v4[key]
	if !ok {
		t.Fatalf("v4 must contain %v, got: %v", key, v4)
	}
	if ttl != nil {
		t.Errorf("static host must stay permanent (nil TTL), got %v", *ttl)
	}
}
