package models

import "testing"

func TestEffectiveRouteMode(t *testing.T) {
	tests := []struct {
		name      string
		iface     string
		wantMode  string
	}{
		{"TPROXY interface", InterfaceTProxy, RouteModeTProxy},
		{"regular interface", "nwg0", RouteModeInterface},
		{"empty interface", "", RouteModeInterface},
		{"lowercase tproxy", "tproxy", RouteModeInterface},
		{"another interface", "br0", RouteModeInterface},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := &Group{Interface: tt.iface}
			if got := g.EffectiveRouteMode(); got != tt.wantMode {
				t.Errorf("Group{Interface: %q}.EffectiveRouteMode() = %q, want %q",
					tt.iface, got, tt.wantMode)
			}
		})
	}
}
