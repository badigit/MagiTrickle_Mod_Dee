package magitrickle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"magitrickle/api"
	"magitrickle/utils/dnsMITMProxy"
	"magitrickle/utils/iptables"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// Start запускает приложение (ядро)
func (a *App) Start(ctx context.Context) (err error) {
	if !a.enabled.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer a.enabled.Store(false)

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic: %v\n%s\n", r, debug.Stack())
			err = errors.New(fmt.Sprintf("panic: %v", r))
		}
	}()

	a.setupLogging()

	a.dnsMITM = dnsMITMProxy.NewDNSMITMProxy(
		net.JoinHostPort(a.config.DNSProxy.Upstream.Address, strconv.Itoa(int(a.config.DNSProxy.Upstream.Port))),
		a.config.DNSProxy.MaxIdleConns,
		a.config.DNSProxy.MaxConcurrent,
		a.config.DNSProxy.Timeout,
	)
	a.dnsMITM.RequestHook = a.dnsRequestHook
	a.dnsMITM.ResponseHook = a.dnsResponseHook

	// dual-upstream: out-of-group домены идут в FallbackUpstream (например ndnproxy 127.0.0.1:53),
	// минуя primary (mihomo). Subnet-rules продолжают работать post-resolve независимо от пути.
	if fb := a.config.DNSProxy.FallbackUpstream; fb != nil {
		a.dnsMITM.SetFallback(
			net.JoinHostPort(fb.Address, strconv.Itoa(int(fb.Port))),
			a.config.DNSProxy.MaxIdleConns,
		)
		a.dnsMITM.UpstreamSelector = a.selectUpstream
	}
	defer func() {
		if a.dnsMITM != nil {
			_ = a.dnsMITM.Close()
		}
	}()

	a.recordsCache = recordsCache.New()
	// Загружаем снапшот кэша с прошлого запуска ДО bringUpRouting: group.Sync
	// наполнит ipset из recordsCache без единого сетевого запроса (автопрогрев
	// после старта/обновления). Закрывает деградацию «рестарт демона опустошает
	// ipset при живых клиентских кэшах» (mt-pqa).
	if err := a.recordsCache.Load(recordsCacheSnapshotLocation); err != nil {
		log.Warn().Err(err).Msg("failed to load records cache snapshot")
	} else {
		log.Info().Int("domains", len(a.recordsCache.ListKnownDomains())).Msg("records cache snapshot loaded")
	}
	a.recordsCache.StartCleanup(ctx, 30*time.Second)
	// На диск пишем только домены, релевантные правилам (+ цели их CNAME-цепочек,
	// это делает SnapshotFiltered): кэш держит ВСЕ резолвы LAN, но переживать
	// рестарт им незачем — ipset наполняется лишь по сматченным (mt-fnj).
	a.recordsCache.StartPersist(ctx, 5*time.Minute, recordsCacheSnapshotLocation, a.isPersistableDomain)

	nfh, err := netfilterTools.New(a.config.Netfilter.IPTables.ChainPrefix, a.config.Netfilter.IPSet.TablePrefix, a.config.Netfilter.DisableIPv4, a.config.Netfilter.DisableIPv6, a.config.Netfilter.StartMarkTableIndex)
	if err != nil {
		return fmt.Errorf("netfilter helper init fail: %w", err)
	}
	a.nfHelper = nfh

	for _, ipt := range []*iptables.IPTables{a.nfHelper.IPTables4, a.nfHelper.IPTables6} {
		if ipt == nil {
			continue
		}
		ipt.RegisterChainPatch("filter", "FORWARD")
		ipt.RegisterChainPatch("mangle", "PREROUTING")
		ipt.RegisterChainPatch("nat", "PREROUTING")
		ipt.RegisterChainPatch("nat", "POSTROUTING")
	}

	if err := a.nfHelper.CleanIPTables(); err != nil {
		return fmt.Errorf("failed to clear iptables: %w", err)
	}

	// Subscribe to link updates BEFORE bringing routing up, otherwise an
	// interface that comes online during the bring-up window would not
	// trigger LinkUpHook and our route on it would never get installed.
	linkUpdateChannel, linkUpdateDone, err := subscribeLinkUpdates()
	if err != nil {
		return err
	}
	defer close(linkUpdateDone)

	// Подписка на изменения адресов: интерфейс может получить IP/шлюз позже
	// поднятия, тогда iface-маршрут пересоздаётся через handleAddr -> AddrChangeHook.
	addrUpdateChannel, addrUpdateDone, err := subscribeAddrUpdates()
	if err != nil {
		return err
	}
	defer close(addrUpdateDone)

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errChan := make(chan error)

	httpServer, err := api.SetupHTTP(a, errChan)
	if err != nil {
		return fmt.Errorf("setup http fail: %w", err)
	}
	defer httpServer.Close()

	unixServer, err := api.SetupUnixSocket(a, errChan)
	if err != nil {
		return fmt.Errorf("setup unix socket fail: %w", err)
	}
	defer unixServer.Close()

	a.startDNSListeners(newCtx, errChan)

	var interfaceAddrs []netlink.Addr
	for _, linkName := range a.config.Link {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return fmt.Errorf("failed to find link %s: %w", linkName, err)
		}
		linkAddrList, err := netlink.AddrList(link, nl.FAMILY_ALL)
		if err != nil {
			return fmt.Errorf("failed to list address of interface %s: %w", linkName, err)
		}
		interfaceAddrs = append(interfaceAddrs, linkAddrList...)
	}

	// Always prepare dnsOverrider object so Pause/Resume can toggle it later,
	// even if the config initially has Enabled=false.
	if !a.config.DNSProxy.DisableRemap53 {
		a.dnsOverrider = a.nfHelper.PortRemap("DNSOR", 53, a.config.DNSProxy.Host.Port, interfaceAddrs)
	}

	if err := a.RebuildSubscriptionGroups(); err != nil {
		return fmt.Errorf("failed to prepare subscription groups: %w", err)
	}

	if a.config.Enabled {
		if err := a.bringUpRouting(); err != nil {
			return err
		}
	} else {
		log.Warn().Msg("MagiTrickle started with app.enabled=false — routing is paused")
	}
	defer func() { _ = a.bringDownRouting() }()

	// Финальный синхронный флеш снапшота — ЗДЕСЬ, а не рядом со StartPersist:
	// defer'ы идут LIFO, поэтому эта регистрация (после bringDownRouting)
	// выполняется ПЕРЕД ним, пока группы ещё включены. Иначе isPersistableDomain
	// опирался бы на уже выключенные группы, отфильтровал бы всё и затёр снапшот
	// пустым — так на проде 2026-07-26 потерялся весь накопленный прогрев
	// (в самом Save на этот случай есть ещё и страховка от пустого слепка).
	// Синхронно, потому что StartPersist-горутину на ctx.Done могут не дождаться.
	defer func() { _, _ = a.recordsCache.Save(recordsCacheSnapshotLocation, a.isPersistableDomain) }()

	a.startSubscriptionSyncLoop(newCtx, errChan)
	a.startStaticSubnetReassertLoop(newCtx)

	for {
		select {
		case event := <-linkUpdateChannel:
			a.handleLink(event)
		case event := <-addrUpdateChannel:
			a.handleAddr(event)
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

// isPersistableDomain — предикат отбора для снапшота recordsCache: на диск идут
// только имена, сматченные активными правилами. Цели их CNAME-цепочек добирает
// сам SnapshotFiltered, поэтому здесь достаточно прямого совпадения.
//
// Побочный эффект осознан: домен, который сматчится ПОСЛЕ добавления правила
// пользователем, в прошлом снапшоте отсутствует — его ipset-запись появится с
// первым же резолвом (или по кнопке «Прогреть»), а не мгновенно после рестарта.
func (a *App) isPersistableDomain(domain string) bool {
	_, ok := a.searchDomain(domain)
	return ok
}

// startStaticSubnetReassertLoop периодически ре-фиксирует permanent
// subnet-записи всех групп (см. Group.ReassertStaticSubnets): ipset-refresh
// правило TPROXY (mt-9g7 C) сбрасывает timeout статической /32-записи при
// новом соединении на её IP; без ре-фиксации такая запись истекла бы после
// паузы в трафике. Интервал 15 мин ограничивает максимальное окно утечки.
func (a *App) startStaticSubnetReassertLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if !a.routingActive.Load() {
					continue
				}
				a.WithConfigRead(func() {
					for _, g := range a.routingGroups() {
						if err := g.ReassertStaticSubnets(); err != nil {
							log.Warn().Err(err).Str("group", g.Name).Msg("failed to reassert static subnets")
						}
					}
				})
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (a *App) ForceCommitIPTables() error {
	if a.nfHelper == nil {
		return nil
	}

	if a.nfHelper.IPTables4 != nil {
		err := a.nfHelper.IPTables4.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit iptables rules: %w", err)
		}
	}

	if a.nfHelper.IPTables6 != nil {
		err := a.nfHelper.IPTables6.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit iptables rules: %w", err)
		}
	}

	return nil
}

func (a *App) setupLogging() {
	// If CLI already set a level below info (debug/trace), keep it.
	if zerolog.GlobalLevel() < zerolog.InfoLevel {
		return
	}
	switch a.config.LogLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "nolevel":
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	case "disabled":
		zerolog.SetGlobalLevel(zerolog.Disabled)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func (a *App) getInterfaceAddresses() ([]netlink.Addr, error) {
	var addrList []netlink.Addr
	for _, linkName := range a.config.Link {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return nil, fmt.Errorf("failed to find link %s: %w", linkName, err)
		}
		linkAddrList, err := netlink.AddrList(link, nl.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("failed to list address of interface %s: %w", linkName, err)
		}
		addrList = append(addrList, linkAddrList...)
	}
	return addrList, nil
}
