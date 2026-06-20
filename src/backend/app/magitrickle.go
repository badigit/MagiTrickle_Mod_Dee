package app

import (
	"context"
	"net"
	"time"

	"magitrickle/config"
	"magitrickle/models"
	"magitrickle/utils/netfilterTools"

	"github.com/vishvananda/netlink"
)

// CapturedDomain — захваченный домен с количеством запросов.
type CapturedDomain struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// CaptureStatus — текущий статус захвата DNS.
type CaptureStatus struct {
	Active    bool             `json:"active"`
	StartedAt *time.Time       `json:"started_at,omitempty"`
	Count     int              `json:"count"`
	Domains   []CapturedDomain `json:"domains,omitempty"`
}

// DNSCapturer — интерфейс для захвата DNS-запросов.
type DNSCapturer interface {
	Start(filterIP string)
	Stop()
	IsActive() bool
	Status(withDomains bool) CaptureStatus
}

type Main interface {
	Config() models.AppConfig
	Groups() []Group
	ClearGroups()
	AddGroup(groupModel *models.Group) error
	RemoveGroupByIndex(idx int)
	ListInterfaces() ([]net.Interface, error)
	InterfaceAliases() map[string]string
	SetInterfaceAliases(aliases map[string]string)
	DnsOverrider() *netfilterTools.PortRemap
	LoadConfig() error
	SaveConfig() error
	LoadInterfaceConfig() error
	SaveInterfaceConfig() error
	ImportConfig(cfg config.Config) error
	ExportConfig() config.Config
	Subscriptions() []*models.Subscription
	ClearSubscriptions()
	AddSubscription(subscription *models.Subscription) error
	RemoveSubscriptionByIndex(idx int)
	RebuildSubscriptionGroups() error
	ForceCommitIPTables() error
	SyncAllGroups()
	DNSCapture() DNSCapturer
	Start(ctx context.Context) (err error)
	Restart()
	StartedAt() time.Time
	IsRoutingActive() bool
	SetEnabled(enabled bool) error
}

type Group interface {
	Enabled() bool
	Model() *models.Group
	AddIPv4Subnet(subnet netfilterTools.IPv4Subnet, ttl netfilterTools.IPSetTimeout) error
	AddIPv6Subnet(subnet netfilterTools.IPv6Subnet, ttl netfilterTools.IPSetTimeout) error
	DelIPv4Subnet(subnet netfilterTools.IPv4Subnet) error
	DelIPv6Subnet(subnet netfilterTools.IPv6Subnet) error
	ListIPv4Subnets() (map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, error)
	ListIPv6Subnets() (map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout, error)
	Enable() error
	Disable() error
	Sync() error
	LinkUpHook(event netlink.LinkUpdate) error
	AddrChangeHook(event netlink.AddrUpdate) error
}
