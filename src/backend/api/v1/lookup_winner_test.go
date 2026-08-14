package v1

import (
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
	var id intID.ID
	copy(id[:], name)
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
