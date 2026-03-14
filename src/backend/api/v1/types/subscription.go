package types

import "magitrickle/utils/intID"

type SubscriptionsReq struct {
	Subscriptions *[]SubscriptionReq `json:"subscriptions"`
}

type SubscriptionsRes struct {
	Subscriptions *[]SubscriptionRes `json:"subscriptions,omitempty"`
}

type SubscriptionReq struct {
	ID         *intID.ID `json:"id" example:"0a1b2c3d" swaggertype:"string"`
	Name       string    `json:"name" example:"Example subscription"`
	Interface  string    `json:"interface" example:"nwg0"`
	Enable     bool      `json:"enable" example:"true"`
	URL        string    `json:"url" example:"https://example.com/list.txt"`
	LastUpdate *int64    `json:"last_update,omitempty" example:"1735689600"`
	Interval   *int64    `json:"interval,omitempty" example:"86400"`
	RulesReq
}

type SubscriptionRes struct {
	ID         intID.ID `json:"id" example:"0a1b2c3d" swaggertype:"string"`
	Name       string   `json:"name" example:"Example subscription"`
	Interface  string   `json:"interface" example:"nwg0"`
	Enable     bool     `json:"enable" example:"true"`
	URL        string   `json:"url" example:"https://example.com/list.txt"`
	LastUpdate int64    `json:"last_update" example:"1735689600"`
	Interval   int64    `json:"interval" example:"86400"`
	RulesRes
}

type SubscriptionSyncRes struct {
	Rules      *[]RuleRes `json:"rules,omitempty"`
	LastUpdate int64      `json:"last_update" example:"1735689600"`
}
