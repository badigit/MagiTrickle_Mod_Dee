package types

type InterfacesRes struct {
	Interfaces []InterfaceRes `json:"interfaces,omitempty"`
}

type InterfaceRes struct {
	ID     string `json:"id" example:"nwg0" swaggertype:"string"`
	Active bool   `json:"active,omitempty" example:"true" swaggertype:"boolean"`
	IP     string `json:"ip,omitempty" example:"10.0.0.2" swaggertype:"string"`
}
