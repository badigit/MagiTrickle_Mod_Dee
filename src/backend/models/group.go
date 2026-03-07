package models

import (
	"magitrickle/utils/intID"
)

const (
	RouteModeInterface = "interface"
	RouteModeTProxy    = "tproxy"

	// InterfaceTProxy is the magic Interface value that selects TPROXY mode.
	InterfaceTProxy = "TPROXY"
)

type Group struct {
	ID        intID.ID
	Name      string
	Color     string
	Interface string
	Enable    bool
	Rules     []*Rule
}

func (g *Group) EffectiveRouteMode() string {
	if g.Interface == InterfaceTProxy {
		return RouteModeTProxy
	}
	return RouteModeInterface
}
