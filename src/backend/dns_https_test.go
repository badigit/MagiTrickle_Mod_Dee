package magitrickle

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

// makeHTTPSRR собирает HTTPS RR (тип 65) в стиле реальных ответов
// (cloudflare.com/claude.ai: Priority 1, Target ".", alpn + hints).
func makeHTTPSRR(owner string, priority uint16, target string, ttl uint32, params ...dns.SVCBKeyValue) *dns.HTTPS {
	return &dns.HTTPS{
		SVCB: dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(owner),
				Rrtype: dns.TypeHTTPS,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Priority: priority,
			Target:   dns.Fqdn(target),
			Value:    params,
		},
	}
}

func v4Hint(ips ...string) *dns.SVCBIPv4Hint {
	h := &dns.SVCBIPv4Hint{}
	for _, s := range ips {
		h.Hint = append(h.Hint, net.ParseIP(s).To4())
	}
	return h
}

func v6Hint(ips ...string) *dns.SVCBIPv6Hint {
	h := &dns.SVCBIPv6Hint{}
	for _, s := range ips {
		h.Hint = append(h.Hint, net.ParseIP(s))
	}
	return h
}

func findParam(rr *dns.HTTPS, key dns.SVCBKey) dns.SVCBKeyValue {
	for _, kv := range rr.Value {
		if kv.Key() == key {
			return kv
		}
	}
	return nil
}

// TestCapAnswersTTLHTTPS — HTTPS/SVCB должны капаться так же, как A/AAAA/CNAME:
// иначе клиент держит hints дольше жизни ipset-записи (корень mt-9g7 через тип 65).
func TestCapAnswersTTLHTTPS(t *testing.T) {
	httpsRR := makeHTTPSRR("example.com", 1, ".", 3600, v4Hint("1.2.3.4"))
	svcbRR := &dns.SVCB{Hdr: dns.RR_Header{Name: "_853._dns.example.com.", Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 7200}, Priority: 1, Target: "."}

	out := capAnswersTTL([]dns.RR{httpsRR, svcbRR}, 300)

	if got := out[0].Header().Ttl; got != 300 {
		t.Errorf("HTTPS client TTL = %d, want 300", got)
	}
	if got := out[1].Header().Ttl; got != 300 {
		t.Errorf("SVCB client TTL = %d, want 300", got)
	}
	// Оригиналы не мутированы (handleMessage должен видеть исходный TTL).
	if httpsRR.Hdr.Ttl != 3600 || svcbRR.Hdr.Ttl != 7200 {
		t.Errorf("original TTL mutated: https=%d svcb=%d", httpsRR.Hdr.Ttl, svcbRR.Hdr.Ttl)
	}
}

// TestStripSVCBIPv6Hints — при активном drop AAAA ipv6hint не должен доезжать
// до клиента (иначе IPv6-адрес провозится «контрабандой» мимо AAAA-фильтра —
// класс T1 из mt-240). Заодно чистится mandatory (RFC 9460 §8: клиент обязан
// отбросить весь RR, если mandatory ссылается на отсутствующий ключ).
func TestStripSVCBIPv6Hints(t *testing.T) {
	rr := makeHTTPSRR("example.com", 1, ".", 3600,
		&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_IPV6HINT}},
		&dns.SVCBAlpn{Alpn: []string{"h3", "h2"}},
		v4Hint("1.2.3.4"),
		v6Hint("2606:4700::1"),
	)

	out := stripSVCBIPv6Hints([]dns.RR{rr})
	got, ok := out[0].(*dns.HTTPS)
	if !ok {
		t.Fatalf("out[0] is %T, want *dns.HTTPS", out[0])
	}

	if findParam(got, dns.SVCB_IPV6HINT) != nil {
		t.Error("ipv6hint must be stripped from client copy")
	}
	if findParam(got, dns.SVCB_MANDATORY) != nil {
		t.Error("emptied mandatory must be removed entirely")
	}
	if findParam(got, dns.SVCB_ALPN) == nil {
		t.Error("alpn must survive (ECH/h3 negotiation must not break)")
	}
	if findParam(got, dns.SVCB_IPV4HINT) == nil {
		t.Error("ipv4hint must survive")
	}

	// Оригинал не тронут: hint и mandatory на месте.
	if findParam(rr, dns.SVCB_IPV6HINT) == nil || findParam(rr, dns.SVCB_MANDATORY) == nil {
		t.Error("original RR mutated (handleMessage must see the untouched RR)")
	}
}

// TestStripSVCBIPv6HintsKeepsMandatoryRest — mandatory с несколькими ключами
// теряет только ipv6hint, остальные коды сохраняются.
func TestStripSVCBIPv6HintsKeepsMandatoryRest(t *testing.T) {
	rr := makeHTTPSRR("example.com", 1, ".", 60,
		&dns.SVCBMandatory{Code: []dns.SVCBKey{dns.SVCB_ALPN, dns.SVCB_IPV6HINT}},
		&dns.SVCBAlpn{Alpn: []string{"h2"}},
		v6Hint("2606:4700::1"),
	)

	out := stripSVCBIPv6Hints([]dns.RR{rr})
	got := out[0].(*dns.HTTPS)

	m, ok := findParam(got, dns.SVCB_MANDATORY).(*dns.SVCBMandatory)
	if !ok {
		t.Fatal("mandatory with remaining keys must be kept")
	}
	if len(m.Code) != 1 || m.Code[0] != dns.SVCB_ALPN {
		t.Errorf("mandatory codes = %v, want [alpn]", m.Code)
	}
}

// TestStripSVCBIPv6HintsNoChangeReusesPointer — RR без ipv6hint не копируется.
func TestStripSVCBIPv6HintsNoChangeReusesPointer(t *testing.T) {
	rr := makeHTTPSRR("example.com", 1, ".", 60, v4Hint("1.2.3.4"))
	aRR := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.ParseIP("1.2.3.4").To4()}

	out := stripSVCBIPv6Hints([]dns.RR{rr, aRR})
	if out[0] != dns.RR(rr) {
		t.Error("HTTPS RR without ipv6hint must be reused as-is")
	}
	if out[1] != dns.RR(aRR) {
		t.Error("non-SVCB RR must be reused as-is")
	}
}

// TestDNSResponseHookHTTPS — интеграция хука: клиент получает капнутый и
// вычищенный RR, а внутренний путь (handleMessage → recordsCache) видит
// оригинал и кладёт ipv4hint в кэш (источник для ipset).
func TestDNSResponseHookHTTPS(t *testing.T) {
	const origTTL = 3600
	app := newTTLCapTestApp(300, 86400) // drop AAAA активен по дефолту

	rr := makeHTTPSRR("example.com", 1, ".", origTTL,
		&dns.SVCBAlpn{Alpn: []string{"h3"}},
		v4Hint("104.16.132.229", "104.16.133.229"),
		v6Hint("2606:4700::6810:84e5"),
	)
	respMsg := dns.Msg{}
	respMsg.Response = true
	respMsg.Answer = []dns.RR{rr}

	clientMsg, err := app.dnsResponseHook(nil, dns.Msg{}, respMsg, "udp")
	if err != nil {
		t.Fatalf("dnsResponseHook error: %v", err)
	}
	if clientMsg == nil {
		t.Fatal("clientMsg is nil, want sanitized copy")
	}

	got := clientMsg.Answer[0].(*dns.HTTPS)
	if got.Hdr.Ttl != 300 {
		t.Errorf("client HTTPS TTL = %d, want 300", got.Hdr.Ttl)
	}
	if findParam(got, dns.SVCB_IPV6HINT) != nil {
		t.Error("client copy must not contain ipv6hint (drop AAAA active)")
	}
	if findParam(got, dns.SVCB_IPV4HINT) == nil {
		t.Error("client copy must keep ipv4hint")
	}

	// Оригинал нетронут.
	if rr.Hdr.Ttl != origTTL || findParam(rr, dns.SVCB_IPV6HINT) == nil {
		t.Error("original RR mutated")
	}

	// Внутренний путь: оба ipv4hint в кэше, ipv6hint — нет (drop AAAA).
	addrs := app.recordsCache.GetAddresses("example.com")
	if len(addrs) != 2 {
		t.Fatalf("recordsCache addresses = %d, want 2 (both ipv4hints)", len(addrs))
	}
	for _, a := range addrs {
		if a.Address.To4() == nil {
			t.Errorf("IPv6 %s must not enter cache while drop AAAA is active", a.Address)
		}
	}
}

// TestProcessHTTPSRecordServiceModeTarget — ServiceMode с Target != ".":
// hints принадлежат target; связь owner→target моделируется как CNAME-алиас,
// чтобы GetAliases/searchDomain матчили правило по owner (замечание Codex №2
// без отдельной service-binding модели).
func TestProcessHTTPSRecordServiceModeTarget(t *testing.T) {
	app := newTTLCapTestApp(300, 86400)

	rr := makeHTTPSRR("example.com", 1, "svc.example-cdn.net", 600, v4Hint("5.6.7.8"))
	app.processHTTPSRecord(rr, "0000", "", "udp")

	// Адрес лежит на target...
	if got := app.recordsCache.GetAddresses("svc.example-cdn.net"); len(got) != 1 {
		t.Fatalf("target addresses = %d, want 1", len(got))
	}
	// ...и достижим через owner (alias-цепочка).
	if got := app.recordsCache.GetAddresses("example.com"); len(got) != 1 {
		t.Fatalf("owner must resolve via alias, got %d addrs", len(got))
	}
}

// TestProcessHTTPSRecordAliasMode — AliasMode (Priority 0) не несёт hints, но
// связь owner→target терять нельзя: follow-up A-ответ на target должен
// матчиться правилом, написанным для owner (замечание Codex №3).
func TestProcessHTTPSRecordAliasMode(t *testing.T) {
	app := newTTLCapTestApp(300, 86400)

	rr := makeHTTPSRR("example.com", 0, "alias-target.example-cdn.net", 600)
	app.processHTTPSRecord(rr, "0000", "", "udp")

	// Симулируем follow-up: A-ответ пришёл на target.
	app.recordsCache.AddAddress("alias-target.example-cdn.net", net.ParseIP("9.9.9.9").To4(), 600)

	if got := app.recordsCache.GetAddresses("example.com"); len(got) != 1 {
		t.Fatalf("owner must resolve через AliasMode chain, got %d addrs", len(got))
	}
}

// TestProcessHTTPSRecordIPv6HintAllowed — при DisableDropAAAA=true ipv6hint
// легален: попадает в кэш (путь к ipset _6) и НЕ вырезается из клиентской копии.
func TestProcessHTTPSRecordIPv6HintAllowed(t *testing.T) {
	app := newTTLCapTestApp(300, 86400)
	app.config.DNSProxy.DisableDropAAAA = true

	rr := makeHTTPSRR("example.com", 1, ".", 600, v6Hint("2606:4700::1"))
	respMsg := dns.Msg{}
	respMsg.Response = true
	respMsg.Answer = []dns.RR{rr}

	clientMsg, err := app.dnsResponseHook(nil, dns.Msg{}, respMsg, "udp")
	if err != nil {
		t.Fatalf("dnsResponseHook error: %v", err)
	}
	// cap=300 < 600 → копия будет; hint в ней должен остаться.
	if clientMsg != nil {
		if findParam(clientMsg.Answer[0].(*dns.HTTPS), dns.SVCB_IPV6HINT) == nil {
			t.Error("ipv6hint must survive when AAAA are allowed")
		}
	}

	addrs := app.recordsCache.GetAddresses("example.com")
	if len(addrs) != 1 || addrs[0].Address.To4() != nil {
		t.Fatalf("ipv6hint must be cached when AAAA allowed, got %v", addrs)
	}
}
