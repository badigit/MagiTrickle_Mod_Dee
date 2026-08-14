package v1

import (
	"encoding/binary"
	"hash/fnv"
	"testing"

	"magitrickle/api/v1/types"
	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/intID"
	"magitrickle/utils/netfilterTools"
)

func ipsetOf(addr [4]byte) map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout {
	return map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout{
		{Address: addr, CIDR: 32}: nil,
	}
}

// ID обязателен и обязан быть уникальным: сбор ipset-хитов дедуплицирует
// группы по нему, и одинаковые (нулевые) ID схлопнули бы разные группы в одну.
func groupWithIface(name, iface string, ipv4 map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, rules ...*models.Rule) *fakeLookupGroup {
	// ID из хэша имени, а не из первых байт: "direct-one" и "direct-two"
	// совпали бы в первых четырёх символах и слились при дедупликации.
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	var id intID.ID
	binary.BigEndian.PutUint32(id[:], h.Sum32())
	return &fakeLookupGroup{
		model: &models.Group{ID: id, Name: name, Enable: true, Interface: iface, Rules: rules},
		ipv4:  ipv4,
	}
}

// M3: в режиме absolute direct-цепочка стоит первой в PREROUTING, поэтому
// пакет завершится в ней независимо от места группы в списке. API обязан
// называть того же победителя, иначе он уверенно указывает не на ту группу.
func TestLookupWinnerDirectAbsoluteBeatsHigherProxyGroup(t *testing.T) {
	ip := [4]byte{10, 20, 30, 40}
	proxy := groupWithIface("AI", models.InterfaceTProxy, ipsetOf(ip))
	direct := groupWithIface("home", models.InterfaceDirect, ipsetOf(ip))

	a := &fakeLookupApp{
		groups:        []app.Group{proxy, direct}, // direct НИЖЕ по списку
		routingActive: true,
		directMode:    models.DirectPriorityAbsolute,
	}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.40"}, CheckIpset: true})
	w := out.Results[0].Winner
	if w == nil {
		t.Fatal("winner отсутствует")
	}
	if w.GroupName != "home" {
		t.Errorf("winner = %q, want home (direct абсолютен)", w.GroupName)
	}
}

// В byOrder тот же набор даёт другого победителя — выигрывает верхняя группа.
func TestLookupWinnerDirectByOrderLosesToHigherGroup(t *testing.T) {
	ip := [4]byte{10, 20, 30, 40}
	proxy := groupWithIface("AI", models.InterfaceTProxy, ipsetOf(ip))
	direct := groupWithIface("home", models.InterfaceDirect, ipsetOf(ip))

	a := &fakeLookupApp{
		groups:        []app.Group{proxy, direct},
		routingActive: true,
		directMode:    models.DirectPriorityByOrder,
	}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.40"}, CheckIpset: true})
	w := out.Results[0].Winner
	if w == nil {
		t.Fatal("winner отсутствует")
	}
	if w.GroupName != "AI" {
		t.Errorf("winner = %q, want AI (direct в общей очереди)", w.GroupName)
	}
}

// M4: ipset рантайм-групп подписок обязан участвовать в выборе победителя —
// иначе для адреса из динамического сета подписки API отвечает «никто».
func TestLookupWinnerCountsSubscriptionIpset(t *testing.T) {
	ip := [4]byte{10, 20, 30, 41}
	sub := groupWithIface("subs", models.InterfaceTProxy, ipsetOf(ip))

	a := &fakeLookupApp{
		groups:        []app.Group{},
		routing:       []app.Group{sub},
		routingActive: true,
		directMode:    models.DirectPriorityAbsolute,
	}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.41"}, CheckIpset: true})
	w := out.Results[0].Winner
	if w == nil {
		t.Fatal("winner отсутствует: ipset подписки не учтён")
	}
	if w.GroupName != "subs" {
		t.Errorf("winner = %q, want subs", w.GroupName)
	}
}

// M5: без check_ipset содержимое сетов неизвестно, поэтому утверждать pending
// нельзя — это выдуманный факт.
func TestLookupNoPendingWithoutIpsetCheck(t *testing.T) {
	g := groupWithIface("AI", models.InterfaceTProxy, nil,
		&models.Rule{Type: models.RuleTypeSubnet, Rule: "10.20.30.0/24", Enable: true})

	a := &fakeLookupApp{groups: []app.Group{g}, routingActive: true, directMode: models.DirectPriorityAbsolute}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.40"}}) // CheckIpset: false
	if w := out.Results[0].Winner; w != nil {
		t.Fatalf("winner = %#v, ожидали отсутствие: состояние ipset не проверялось", w)
	}
}

// M5 (вторая половина): при снятом роутинге ни одна цепочка MT не активна,
// поэтому победителя «прямо сейчас» нет — правило сработает лишь потом.
func TestLookupWinnerPendingWhenRoutingPaused(t *testing.T) {
	g := groupWithIface("AI", models.InterfaceTProxy, nil,
		&models.Rule{Type: models.RuleTypeSubnet, Rule: "10.20.30.0/24", Enable: true})

	a := &fakeLookupApp{groups: []app.Group{g}, routingActive: false, directMode: models.DirectPriorityAbsolute}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.40"}, CheckIpset: true})
	w := out.Results[0].Winner
	if w == nil {
		t.Fatal("winner отсутствует")
	}
	if !w.Pending {
		t.Error("pending = false, но роутинг снят — сейчас трафик идёт мимо")
	}
}

// M6: у диапазона нет одного победителя — разные адреса внутри него могут
// попасть в разные группы, а правило может покрывать лишь его часть.
func TestLookupNoWinnerForCIDRQuery(t *testing.T) {
	g := groupWithIface("AI", models.InterfaceTProxy, nil,
		&models.Rule{Type: models.RuleTypeSubnet, Rule: "10.20.30.128/25", Enable: true})

	a := &fakeLookupApp{groups: []app.Group{g}, routingActive: true, directMode: models.DirectPriorityAbsolute}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.0/24"}, CheckIpset: true})
	got := out.Results[0]
	if got.Winner != nil {
		t.Fatalf("winner = %#v, у CIDR-запроса единого победителя нет", got.Winner)
	}
	if len(got.RuleHits) == 0 {
		t.Error("rule_hits пропали: список совпадений для диапазона по-прежнему нужен")
	}
}

// M3 (вторая половина): direct-цепочки вставляются каждая в позицию 1, то есть
// ложатся в PREROUTING в обратном порядке включения. При overlap выигрывает
// ПОСЛЕДНЯЯ direct-группа списка, а не первая.
func TestLookupWinnerLastDirectWinsAmongSeveral(t *testing.T) {
	ip := [4]byte{10, 20, 30, 42}
	first := groupWithIface("direct-one", models.InterfaceDirect, ipsetOf(ip))
	second := groupWithIface("direct-two", models.InterfaceDirect, ipsetOf(ip))

	a := &fakeLookupApp{
		groups:        []app.Group{first, second},
		routingActive: true,
		directMode:    models.DirectPriorityAbsolute,
	}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.42"}, CheckIpset: true})
	w := out.Results[0].Winner
	if w == nil {
		t.Fatal("winner отсутствует")
	}
	if w.GroupName != "direct-two" {
		t.Errorf("winner = %q, want direct-two (её цепочка вставлена последней, значит стоит первой)", w.GroupName)
	}
}

// M5 (домен): при снятом роутинге группы выключены и trie пуст, поэтому
// победителя по домену не существует. Ответ обязан сообщать, что роутинг снят,
// иначе пустой winner читается как «правил нет».
func TestLookupReportsRoutingInactive(t *testing.T) {
	g := groupWithIface("AI", models.InterfaceTProxy, nil,
		&models.Rule{Type: models.RuleTypeDomain, Rule: "claude.ai", Enable: true})

	a := &fakeLookupApp{groups: []app.Group{g}, routingActive: false}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"claude.ai"}})
	if out.RoutingActive {
		t.Error("routing_active = true, но роутинг снят")
	}
	if out.Results[0].Winner != nil {
		t.Error("winner назван при снятом роутинге: ни одной цепочки MT сейчас нет")
	}
}

func TestLookupReportsRoutingActive(t *testing.T) {
	g := groupWithIface("AI", models.InterfaceTProxy, nil)
	a := &fakeLookupApp{groups: []app.Group{g}, routingActive: true}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"example.org"}})
	if !out.RoutingActive {
		t.Error("routing_active = false при поднятом роутинге")
	}
}

// #7: рантайм-группа подписки обязана помечаться source=subscription, иначе
// пользователь ищет правило не там, где оно лежит.
func TestLookupIpsetWinnerFromSubscriptionHasRightSource(t *testing.T) {
	ip := [4]byte{10, 20, 30, 43}
	sub := groupWithIface("subs", models.InterfaceTProxy, ipsetOf(ip))

	a := &fakeLookupApp{
		groups:        []app.Group{},
		routing:       []app.Group{sub},
		subs:          []*models.Subscription{{ID: sub.model.ID, Name: "subs", Enable: true}},
		routingActive: true,
	}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.43"}, CheckIpset: true})
	w := out.Results[0].Winner
	if w == nil {
		t.Fatal("winner отсутствует")
	}
	if w.Source != "subscription" {
		t.Errorf("source = %q, want subscription", w.Source)
	}
}

// #7 (вторая половина): ID уникальны лишь внутри базовых групп и внутри
// подписок. Одинаковый ID у базовой группы и подписки не должен приводить к
// тому, что одна подавляет другую при дедупликации ipset-хитов.
func TestLookupIpsetHitsNotDedupedAcrossSources(t *testing.T) {
	ip := [4]byte{10, 20, 30, 44}
	base := groupWithIface("base", models.InterfaceTProxy, ipsetOf(ip))
	sub := groupWithIface("base", models.InterfaceDirect, ipsetOf(ip)) // тот же ID: имя одинаковое
	sub.model.Name = "subs"

	a := &fakeLookupApp{
		groups:        []app.Group{base},
		routing:       []app.Group{base, sub},
		subs:          []*models.Subscription{{ID: sub.model.ID, Name: "subs", Enable: true}},
		routingActive: true,
		directMode:    models.DirectPriorityAbsolute,
	}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"10.20.30.44"}, CheckIpset: true})
	got := out.Results[0]
	if len(got.IpsetHits) != 2 {
		t.Fatalf("ipset_hits = %d, want 2: базовая группа и подписка с одинаковым ID — разные записи", len(got.IpsetHits))
	}
	if got.Winner == nil || got.Winner.GroupName != "subs" {
		t.Errorf("winner = %#v, want subs: direct выигрывает в absolute", got.Winner)
	}
}
