package types

type InterfacesRes struct {
	Interfaces []InterfaceRes `json:"interfaces,omitempty"`
}

type InterfaceRes struct {
	ID     string `json:"id" example:"nwg0" swaggertype:"string"`
	Active bool   `json:"active,omitempty" example:"true" swaggertype:"boolean"`
	IP     string `json:"ip,omitempty" example:"10.0.0.2" swaggertype:"string"`
	// Outgoing reports whether the interface carries the router's own egress
	// (has a default route via it). Only such interfaces can answer the
	// external-IP probe; incoming/server tunnels (e.g. an SSTP server endpoint)
	// are false, so the UI must not auto-test them.
	Outgoing bool `json:"outgoing,omitempty" example:"true" swaggertype:"boolean"`
}
