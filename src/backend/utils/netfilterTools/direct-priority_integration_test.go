//go:build integration && linux

// Интеграционные тесты приоритета direct-групп против НАСТОЯЩЕГО netfilter.
//
// Тег общий с остальными интеграционными тестами пакета (client-routing), так
// что все они запускаются одной командой. Запускать через
// scripts/integration-test.sh: он поднимает пару network namespace,
// соединённых veth, и стартует тесты ВНУТРИ router-ns.
// Тогда и вызовы iptables (exec), и netlink-сокеты ipset из рабочего кода
// попадают в изолированный namespace сами — продакшен-роутер и хостовые
// правила не затрагиваются вообще.
//
// Ценность поверх unit-тестов на FakeIPTables: те проверяют, какие команды МЫ
// СФОРМИРОВАЛИ, а здесь ядро реально принимает правила и реально принимает
// решение по проходящему пакету. Это ловит то, чего фейк не увидит:
// несовместимый набор match, неверную позицию в цепочке, ошибку в порядке
// таблиц.
package netfilterTools

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"magitrickle/utils/iptables"
)

const (
	itestDirectSet   = "itest_direct_4"
	itestIfaceSet    = "itest_iface_4"
	itestDirectChain = "ITEST_DIRECT"
	itestIfaceChain  = "ITEST_IFACE"
)

func requireNetnsEnv(t *testing.T) (clientNS, targetIP string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("нужен root: запускать через scripts/integration-test.sh")
	}
	clientNS = os.Getenv("MT_ITEST_CLIENT_NS")
	targetIP = os.Getenv("MT_ITEST_TARGET_IP")
	if clientNS == "" || targetIP == "" {
		t.Skip("нет MT_ITEST_* окружения: запускать через scripts/integration-test.sh")
	}
	return clientNS, targetIP
}

func mustRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

// resetNetfilter возвращает namespace к чистому состоянию между режимами:
// иначе правила предыдущего прогона исказили бы и порядок, и счётчики.
func resetNetfilter() {
	for _, table := range []string{"mangle", "nat", "filter"} {
		_ = exec.Command("iptables", "-t", table, "-F").Run()
	}
	for _, chain := range []string{itestDirectChain, itestIfaceChain} {
		for _, table := range []string{"mangle", "nat", "filter"} {
			_ = exec.Command("iptables", "-t", table, "-F", chain).Run()
			_ = exec.Command("iptables", "-t", table, "-X", chain).Run()
		}
	}
	for _, set := range []string{itestDirectSet, itestIfaceSet} {
		_ = exec.Command("ipset", "destroy", set).Run()
	}
}

// chainPacketCount — сколько пакетов ВОШЛО в цепочку группы, то есть счётчик
// её jump-правила в PREROUTING. Это и есть ответ ядра на вопрос «кто выиграл
// overlap»: цепочка, до которой очередь не дошла, не получит ни одного пакета.
//
// Считать по правилам ВНУТРИ цепочки нельзя: iptables инкрементирует счётчик
// правила только при совпадении, а первым в каждой цепочке идёт client-bypass
// guard, который в этом тесте не совпадает никогда и всегда показывал бы ноль.
func chainPacketCount(t *testing.T, table, chain string) int {
	t.Helper()
	out := mustRun(t, "iptables", "-t", table, "-L", "PREROUTING", "-v", "-n", "-x")
	splitter := regexp.MustCompile(`\s+`)
	for _, line := range strings.Split(out, "\n") {
		fields := splitter.Split(strings.TrimSpace(line), -1)
		// pkts bytes target ...
		if len(fields) < 3 || fields[2] != chain {
			continue
		}
		n, err := strconv.Atoi(fields[0])
		if err != nil {
			t.Fatalf("не разобрал счётчик пакетов для %s: %q", chain, line)
		}
		return n
	}
	t.Fatalf("цепочка %s не подключена к %s/PREROUTING:\n%s", chain, table, out)
	return 0
}

// setupGroups поднимает две группы, чьи ipset ПЕРЕСЕКАЮТСЯ по одному IP:
// interface-группу (MARK, поднимается первой — она «выше в списке») и
// direct-группу. Позиция direct-цепочки определяется режимом byOrder.
func setupGroups(t *testing.T, targetIP string, byOrder bool) {
	t.Helper()

	mustRun(t, "ipset", "create", itestDirectSet, "hash:net", "family", "inet")
	mustRun(t, "ipset", "create", itestIfaceSet, "hash:net", "family", "inet")
	mustRun(t, "ipset", "add", itestDirectSet, targetIP)
	mustRun(t, "ipset", "add", itestIfaceSet, targetIP)

	ipt := iptables.NewIPTables(iptables.NewRealIPTables())
	ipt.RegisterChainPatch("mangle", "PREROUTING")
	ipt.RegisterChainPatch("nat", "PREROUTING")
	ipt.RegisterChainPatch("nat", "POSTROUTING")
	ipt.RegisterChainPatch("filter", "FORWARD")

	nh := &Helper{IPTables4: ipt}
	nh.SetDirectPriorityByOrder(byOrder)

	// Сеты client-bypass создаём штатным кодом: guard на них добавляется в
	// КАЖДУЮ цепочку, и без реально существующих сетов iptables-restore
	// отвергает весь батч. Именно это отличие от FakeIPTables тест и ловит.
	if _, err := nh.SetupClientBypass(nil); err != nil {
		t.Fatalf("SetupClientBypass: %v", err)
	}
	t.Cleanup(func() { _ = nh.DestroyClientBypass() })

	// Группа выше по списку: interface-режим. Поднимается первой, её цепочка
	// цепляется Append — как это делает bringUpRouting, идущий по группам в
	// порядке конфига. Blackhole вместо реального линка: нас интересует только
	// MARK-путь в mangle, а не маршруты.
	ifaceGroup := &IPSetToLink{
		chainName: itestIfaceChain,
		ifaceName: Blackhole,
		ipset:     &IPSet{ipsetName: strings.TrimSuffix(itestIfaceSet, "_4")},
		nh:        nh,
		mark:      0x4d2,
	}
	if err := ifaceGroup.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("interface-группа: %v", err)
	}

	directGroup := &IPSetToLink{
		chainName: itestDirectChain,
		ifaceName: Direct,
		ipset:     &IPSet{ipsetName: strings.TrimSuffix(itestDirectSet, "_4")},
		nh:        nh,
	}
	if err := directGroup.insertIPTablesRules(ipt); err != nil {
		t.Fatalf("direct-группа: %v", err)
	}
}

// dumpNetfilter печатает фактическое состояние namespace. Вызывается только
// при падении: разбирать несовпадение счётчиков без дампа правил бессмысленно.
func dumpNetfilter(t *testing.T) {
	t.Helper()
	t.Logf("mangle -S:\n%s", mustRun(t, "iptables", "-t", "mangle", "-S"))
	t.Logf("mangle PREROUTING counters:\n%s", mustRun(t, "iptables", "-t", "mangle", "-L", "PREROUTING", "-v", "-n", "-x"))
	t.Logf("ipset list:\n%s", mustRun(t, "ipset", "list", "-n"))
}

func sendProbeTraffic(clientNS, targetIP string) {
	// Ответа не будет (целевой IP никуда не ведёт) — важен сам проход пакета
	// через PREROUTING роутера, поэтому ошибка ping игнорируется осознанно.
	_ = exec.Command("ip", "netns", "exec", clientNS,
		"ping", "-c", "2", "-W", "1", targetIP).Run()
}

// TestNetnsDirectPriorityAbsolute — дефолтный режим: IP лежит и в direct-, и в
// interface-группе, но пакет обязан достаться direct, хотя interface-группа
// стоит выше в списке.
func TestNetnsDirectPriorityAbsolute(t *testing.T) {
	clientNS, targetIP := requireNetnsEnv(t)
	resetNetfilter()
	t.Cleanup(resetNetfilter)

	setupGroups(t, targetIP, false)
	sendProbeTraffic(clientNS, targetIP)

	direct := chainPacketCount(t, "mangle", itestDirectChain)
	iface := chainPacketCount(t, "mangle", itestIfaceChain)

	if direct == 0 {
		t.Error("direct-цепочка не поймала ни одного пакета: в absolute она обязана перебивать группы выше по списку")
	}
	if iface != 0 {
		t.Errorf("interface-цепочка поймала %d пакетов, ожидалось 0: direct должен был терминировать обход раньше", iface)
	}
	t.Logf("absolute: direct=%d pkts, iface=%d pkts", direct, iface)
	if t.Failed() {
		dumpNetfilter(t)
	}
}

// TestNetnsDirectPriorityByOrder — зеркальный случай: та же пара групп и тот же
// overlap, но direct стоит в общей очереди, поэтому выигрывает группа выше.
// Именно эта пара тестов доказывает, что режим меняет РЕАЛЬНОЕ решение ядра,
// а не только вид дампа правил.
func TestNetnsDirectPriorityByOrder(t *testing.T) {
	clientNS, targetIP := requireNetnsEnv(t)
	resetNetfilter()
	t.Cleanup(resetNetfilter)

	setupGroups(t, targetIP, true)
	sendProbeTraffic(clientNS, targetIP)

	direct := chainPacketCount(t, "mangle", itestDirectChain)
	iface := chainPacketCount(t, "mangle", itestIfaceChain)

	if iface == 0 {
		t.Error("interface-цепочка не поймала пакеты: в byOrder группа выше по списку обязана выигрывать overlap")
	}
	if direct != 0 {
		t.Errorf("direct-цепочка поймала %d пакетов, ожидалось 0: в byOrder её очередь наступает позже", direct)
	}
	t.Logf("byOrder: direct=%d pkts, iface=%d pkts", direct, iface)
}
