package types

import (
	"magitrickle/utils/intID"
)

type GroupsReq struct {
	Groups *[]GroupReq `json:"groups"`
}

type GroupsRes struct {
	Groups *[]GroupRes `json:"groups,omitempty"`
}

type GroupReq struct {
	ID        *intID.ID `json:"id" example:"0a1b2c3d" swaggertype:"string"`
	Name      string    `json:"name" example:"Routing"`
	Color     string    `json:"color" example:"#ffffff"`
	Interface string    `json:"interface" example:"nwg0"`
	Enable    *bool     `json:"enable" example:"true" TODO:"Make required after 1.0.0"`
	RulesReq
}

type GroupRes struct {
	ID        intID.ID `json:"id" example:"0a1b2c3d" swaggertype:"string"`
	Name      string   `json:"name" example:"Routing"`
	Color     string   `json:"color" example:"#ffffff"`
	Interface string   `json:"interface" example:"nwg0"`
	Enable    bool     `json:"enable" example:"true"`
	IPCount   *int     `json:"ip_count,omitempty"`
	RulesRes
}

type TProxyStatusRes struct {
	Configured bool                `json:"configured"`
	Port       uint16              `json:"port"`
	Listening  bool                `json:"listening"`
	Groups     []TProxyGroupStatus `json:"groups"`
}

type TProxyGroupStatus struct {
	ID      intID.ID `json:"id" swaggertype:"string"`
	Name    string   `json:"name"`
	Enable  bool     `json:"enable"`
	IPCount int      `json:"ip_count"`
}
