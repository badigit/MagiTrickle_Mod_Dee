package magitrickle

import (
	"net"
	"testing"
	"time"

	"magitrickle/constant"
	"magitrickle/utils/recordsCache"
	"magitrickle/utils/trie"

	"github.com/miekg/dns"
)

// TestCapAnswersTTL проверяет чистую логику капа: A/AAAA/CNAME с TTL > cap
// капаются в КОПИИ, исходные RR не мутируются (cap не должен протечь в ipset),
// записи с TTL <= cap и прочие типы остаются как есть.
func TestCapAnswersTTL(t *testing.T) {
	aBig := &dns.A{
		Hdr: dns.RR_Header{Name: "a.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("1.2.3.4").To4(),
	}
	aSmall := &dns.A{
		Hdr: dns.RR_Header{Name: "b.example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
		A:   net.ParseIP("5.6.7.8").To4(),
	}
	cname := &dns.CNAME{
		Hdr:    dns.RR_Header{Name: "c.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 900},
		Target: "a.example.com.",
	}
	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: "d.example.com.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"hello"},
	}

	answers := []dns.RR{aBig, aSmall, cname, txt}
	out := capAnswersTTL(answers, 120)

	if len(out) != 4 {
		t.Fatalf("len(out) = %d, want 4", len(out))
	}

	// aBig: TTL > cap → капнут в КОПИИ до 120, оригинал не тронут.
	if got := out[0].Header().Ttl; got != 120 {
		t.Errorf("out[0] (A big) TTL = %d, want 120", got)
	}
	if aBig.Hdr.Ttl != 3600 {
		t.Errorf("original A big TTL mutated: %d, want 3600 (cap leaked!)", aBig.Hdr.Ttl)
	}
	if out[0] == dns.RR(aBig) {
		t.Error("out[0] must be a COPY of aBig, got same pointer")
	}

	// aSmall: TTL <= cap → без изменений, тот же указатель.
	if out[1] != dns.RR(aSmall) {
		t.Error("out[1] (A small) must reuse the same pointer")
	}
	if got := out[1].Header().Ttl; got != 30 {
		t.Errorf("out[1] (A small) TTL = %d, want 30", got)
	}

	// CNAME: TTL > cap → капнут в копии.
	if got := out[2].Header().Ttl; got != 120 {
		t.Errorf("out[2] (CNAME) TTL = %d, want 120", got)
	}
	if cname.Hdr.Ttl != 900 {
		t.Errorf("original CNAME TTL mutated: %d, want 900", cname.Hdr.Ttl)
	}

	// TXT: тип не капается — тот же указатель, TTL нетронут.
	if out[3] != dns.RR(txt) {
		t.Error("out[3] (TXT) must reuse the same pointer (non-cappable type)")
	}
	if got := out[3].Header().Ttl; got != 3600 {
		t.Errorf("out[3] (TXT) TTL = %d, want 3600", got)
	}
}

// newTTLCapTestApp собирает минимальный App без реальных ipset/групп: searchDomain
// вернёт false, поэтому handleMessage наполнит только recordsCache (безопасно).
func newTTLCapTestApp(clientTTLCap, additionalTTL uint32) *App {
	a := &App{config: constant.DefaultAppConfig}
	a.config.DNSProxy.ClientTTLCap = clientTTLCap
	a.config.Netfilter.IPSet.AdditionalTTL = additionalTTL
	a.recordsCache = recordsCache.New()
	a.domainTrie.Store(trie.New())
	emptyGroups := make([]*Group, 0)
	a.groups.Store(&emptyGroups)
	emptySubGroups := make([]*Group, 0)
	a.subscriptionGroups.Store(&emptySubGroups)
	return a
}

// TestDNSResponseHookTTLCap — ключевой тест acceptance-критерия mt-9g7:
// клиентский ответ отдаётся с TTL <= cap, но в кэш/ipset уходит ОРИГИНАЛЬНЫЙ
// TTL (origTTL + AdditionalTTL). Cap не должен протечь.
func TestDNSResponseHookTTLCap(t *testing.T) {
	const origTTL = 3600
	const additionalTTL = 3600
	const cap = 120
	app := newTTLCapTestApp(cap, additionalTTL)

	aRR := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: origTTL},
		A:   net.ParseIP("93.184.216.34").To4(),
	}
	respMsg := dns.Msg{}
	respMsg.Response = true
	respMsg.Rcode = dns.RcodeSuccess
	respMsg.Answer = []dns.RR{aRR}

	before := time.Now()
	clientMsg, err := app.dnsResponseHook(nil, dns.Msg{}, respMsg, "udp")
	if err != nil {
		t.Fatalf("dnsResponseHook error: %v", err)
	}
	if clientMsg == nil {
		t.Fatal("clientMsg is nil, want capped response")
	}

	// 1. Клиент получает capped TTL.
	if len(clientMsg.Answer) != 1 {
		t.Fatalf("clientMsg.Answer len = %d, want 1", len(clientMsg.Answer))
	}
	if got := clientMsg.Answer[0].Header().Ttl; got != cap {
		t.Errorf("client TTL = %d, want %d", got, cap)
	}

	// 2. Оригинальный RR не мутирован (cap не протёк в общий указатель).
	if aRR.Hdr.Ttl != origTTL {
		t.Errorf("original RR TTL mutated: %d, want %d", aRR.Hdr.Ttl, origTTL)
	}

	// 3. В recordsCache (источник TTL для ipset) ушёл ОРИГИНАЛЬНЫЙ TTL:
	//    deadline ≈ now + origTTL + additionalTTL, а НЕ now + cap.
	addrs := app.recordsCache.GetAddresses("example.com")
	if len(addrs) != 1 {
		t.Fatalf("recordsCache addresses = %d, want 1", len(addrs))
	}
	remaining := addrs[0].Deadline.Sub(before).Seconds()
	wantMin := float64(origTTL + additionalTTL - 30)
	wantMax := float64(origTTL + additionalTTL + 30)
	if remaining < wantMin || remaining > wantMax {
		t.Errorf("ipset TTL (via recordsCache deadline) = %.0fs, want ~%ds (cap leaked into ipset!)",
			remaining, origTTL+additionalTTL)
	}
}

// TestDNSResponseHookTTLCapDisabled — при ClientTTLCap==0 и выключенном drop AAAA
// хук отдаёт оригинальный ответ без изменений (nil), сохраняя старое поведение.
func TestDNSResponseHookTTLCapDisabled(t *testing.T) {
	app := newTTLCapTestApp(0, 3600)
	app.config.DNSProxy.DisableDropAAAA = true // выключаем фильтрацию AAAA

	aRR := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600},
		A:   net.ParseIP("93.184.216.34").To4(),
	}
	respMsg := dns.Msg{}
	respMsg.Response = true
	respMsg.Rcode = dns.RcodeSuccess
	respMsg.Answer = []dns.RR{aRR}

	clientMsg, err := app.dnsResponseHook(nil, dns.Msg{}, respMsg, "udp")
	if err != nil {
		t.Fatalf("dnsResponseHook error: %v", err)
	}
	if clientMsg != nil {
		t.Errorf("clientMsg = %v, want nil (unmodified passthrough)", clientMsg)
	}
}
