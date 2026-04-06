package magitrickle

import (
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"magitrickle/app"
)

// DNSCapture собирает уникальные доменные имена из DNS-запросов.
type DNSCapture struct {
	active    atomic.Bool
	startedAt time.Time
	mu        sync.Mutex
	domains   map[string]int // domain → count
	filterIP  string         // если не пусто, захватывать только от этого IP
}

// NewDNSCapture создаёт новый экземпляр DNSCapture.
func NewDNSCapture() *DNSCapture {
	return &DNSCapture{
		domains: make(map[string]int),
	}
}

// Start начинает захват DNS-запросов. filterIP — опциональный фильтр по IP клиента.
func (c *DNSCapture) Start(filterIP string) {
	c.mu.Lock()
	c.domains = make(map[string]int)
	c.startedAt = time.Now()
	c.filterIP = filterIP
	c.mu.Unlock()
	c.active.Store(true)
}

// Stop останавливает захват DNS-запросов.
func (c *DNSCapture) Stop() {
	c.active.Store(false)
}

// IsActive возвращает true, если захват активен.
func (c *DNSCapture) IsActive() bool {
	return c.active.Load()
}

// Record записывает доменное имя, если захват активен.
// clientIP — IP-адрес клиента, сделавшего запрос (может содержать порт).
func (c *DNSCapture) Record(name string, clientIP string) {
	if !c.active.Load() {
		return
	}
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return
	}
	c.mu.Lock()
	if c.filterIP != "" {
		host := clientIP
		// Убираем порт если есть (например "192.168.1.5:12345")
		if h, _, err := net.SplitHostPort(clientIP); err == nil {
			host = h
		}
		if host != c.filterIP {
			c.mu.Unlock()
			return
		}
	}
	c.domains[name]++
	c.mu.Unlock()
}

// results возвращает захваченные домены, отсортированные по количеству запросов.
func (c *DNSCapture) results() []app.CapturedDomain {
	c.mu.Lock()
	result := make([]app.CapturedDomain, 0, len(c.domains))
	for domain, count := range c.domains {
		result = append(result, app.CapturedDomain{Domain: domain, Count: count})
	}
	c.mu.Unlock()

	sort.Slice(result, func(i, j int) bool {
		return result[i].Count > result[j].Count
	})
	return result
}

// Status возвращает текущий статус захвата.
func (c *DNSCapture) Status(withDomains bool) app.CaptureStatus {
	status := app.CaptureStatus{
		Active: c.active.Load(),
	}
	c.mu.Lock()
	status.Count = len(c.domains)
	if status.Active {
		t := c.startedAt
		status.StartedAt = &t
	}
	c.mu.Unlock()

	if withDomains {
		status.Domains = c.results()
	}
	return status
}
