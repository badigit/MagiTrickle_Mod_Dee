package magitrickle

import (
	"fmt"
	"net"
	"slices"

	"magitrickle/constant"
	"magitrickle/models"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func subscribeLinkUpdates() (chan netlink.LinkUpdate, chan struct{}, error) {
	linkUpdateChannel := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	if err := netlink.LinkSubscribe(linkUpdateChannel, done); err != nil {
		return nil, nil, fmt.Errorf("failed to subscribe to link updates: %w", err)
	}
	return linkUpdateChannel, done, nil
}

func subscribeAddrUpdates() (chan netlink.AddrUpdate, chan struct{}, error) {
	addrUpdateChannel := make(chan netlink.AddrUpdate)
	done := make(chan struct{})
	if err := netlink.AddrSubscribe(addrUpdateChannel, done); err != nil {
		return nil, nil, fmt.Errorf("failed to subscribe to addr updates: %w", err)
	}
	return addrUpdateChannel, done, nil
}

// handleLink обрабатывает события изменения состояния сетевых интерфейсов
func (a *App) handleLink(event netlink.LinkUpdate) {
	switch event.Header.Type {
	case unix.RTM_NEWLINK:
		linkAttrs := event.Link.Attrs()
		// Только UP-события: интерфейс может появиться сначала в DOWN и
		// дойти до UP позже отдельным NEWLINK; вызывать LinkUpHook на
		// down-интерфейсе бессмысленно (route не установится).
		if linkAttrs.Flags&net.FlagUp == 0 {
			break
		}
		ifaceName := linkAttrs.Name
		if !slices.Contains(constant.IgnoredInterfaces, ifaceName) {
			log.Debug().
				Str("interface", ifaceName).
				Int("type", int(event.Header.Type)).
				Msg("interface up")
		}
		for _, group := range a.routingGroups() {
			if group.Group.EffectiveRouteMode() != models.RouteModeInterface {
				continue
			}
			if group.Interface != ifaceName {
				continue
			}
			if err := group.LinkUpHook(event); err != nil {
				log.Error().
					Err(err).
					Str("group", group.ID.String()).
					Msg("error while handling interface up")
			}
		}
	case unix.RTM_DELLINK:
		log.Debug().
			Str("interface", event.Link.Attrs().Name).
			Int("type", int(event.Header.Type)).
			Msg("interface del")
	}
}

// handleAddr обрабатывает события изменения IP-адресов сетевых интерфейсов.
// Реагирует только на добавление адреса (NewAddr): когда интерфейс получает
// адрес/шлюз позже момента поднятия (VPN/PPP/DHCP), это позволяет пересоздать
// iface-маршрут с актуальным шлюзом без перезапуска группы.
func (a *App) handleAddr(event netlink.AddrUpdate) {
	if !event.NewAddr {
		return
	}

	iface, err := netlink.LinkByIndex(event.LinkIndex)
	if err != nil {
		log.Error().Err(err).Int("linkIndex", event.LinkIndex).Msg("failed to get interface for addr update")
		return
	}

	ifaceName := iface.Attrs().Name
	if !slices.Contains(constant.IgnoredInterfaces, ifaceName) {
		log.Debug().
			Str("interface", ifaceName).
			Str("addr", event.LinkAddress.String()).
			Msg("interface address changed")
	}

	for _, group := range a.routingGroups() {
		if group.Group.EffectiveRouteMode() != models.RouteModeInterface {
			continue
		}
		if group.Interface != ifaceName {
			continue
		}
		if err := group.AddrChangeHook(event); err != nil {
			log.Error().
				Err(err).
				Str("group", group.ID.String()).
				Msg("error while handling interface addr change")
		}
	}
}
