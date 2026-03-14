package subscriptions

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"strings"
	"syscall"
	"time"

	"magitrickle/models"
	"magitrickle/utils/intID"

	"github.com/rs/zerolog/log"
)

const (
	FetchTimeout         = 20 * time.Second
	FetchFallbackTimeout = 8 * time.Second
)

// FetchRules fetches subscription rules from the given URL.
// It tries a direct request first; on failure it retries through each
// active network interface (SO_BINDTODEVICE) until one succeeds.
func FetchRules(ctx context.Context, rawURL string) ([]*models.Rule, error) {
	rawURL = strings.TrimSpace(rawURL)
	if idx := strings.IndexByte(rawURL, '#'); idx >= 0 {
		rawURL = rawURL[:idx]
	}

	parsedURL, err := neturl.ParseRequestURI(rawURL)
	if err != nil {
		return nil, fmt.Errorf("invalid subscription url: %w", err)
	}

	fetchURL := parsedURL.String()

	// Try direct first
	resp, directErr := doFetch(ctx, fetchURL, "", FetchTimeout)
	if directErr != nil {
		log.Debug().Err(directErr).Str("url", fetchURL).Msg("direct fetch failed, trying via interfaces")

		// Fallback: try each active interface
		resp, err = fetchViaInterfaces(ctx, fetchURL)
		if err != nil {
			// Return the original direct error — it's more informative
			return nil, fmt.Errorf("failed to fetch subscription rules: %w", directErr)
		}
	}
	defer resp.Body.Close()

	return parseRulesFromBody(resp)
}

func fetchViaInterfaces(ctx context.Context, fetchURL string) (*http.Response, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		hasIPv4 := false
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil && !ipnet.IP.IsLoopback() {
				hasIPv4 = true
				break
			}
		}
		if !hasIPv4 {
			continue
		}

		resp, err := doFetch(ctx, fetchURL, iface.Name, FetchFallbackTimeout)
		if err != nil {
			log.Debug().Err(err).Str("url", fetchURL).Str("interface", iface.Name).Msg("fetch via interface failed")
			continue
		}
		log.Debug().Str("url", fetchURL).Str("interface", iface.Name).Msg("fetch via interface succeeded")
		return resp, nil
	}

	return nil, fmt.Errorf("all interfaces failed")
}

func doFetch(ctx context.Context, url, ifaceName string, timeout time.Duration) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "MagiTrickle/Subscriptions")

	transport := &http.Transport{}
	if ifaceName != "" {
		dialer := &net.Dialer{
			Timeout: timeout,
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					_ = syscall.BindToDevice(int(fd), ifaceName)
				})
			},
		}
		transport.DialContext = dialer.DialContext
	}

	client := &http.Client{Timeout: timeout, Transport: transport}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		resp.Body.Close()
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	return resp, nil
}

func parseRulesFromBody(resp *http.Response) ([]*models.Rule, error) {
	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	seen := make(map[string]struct{})
	rules := make([]*models.Rule, 0, 128)

	for scanner.Scan() {
		ruleValue, ruleType, ok := ParseRuleLine(scanner.Text())
		if !ok {
			continue
		}

		key := ruleType + "\x00" + ruleValue
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}

		rules = append(rules, &models.Rule{
			ID:     intID.RandomID(),
			Type:   ruleType,
			Rule:   ruleValue,
			Enable: true,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed reading subscription rules: %w", err)
	}

	return rules, nil
}

func ParseRuleLine(line string) (string, string, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}

	if idx := strings.Index(line, " #"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}

	switch {
	case strings.HasPrefix(line, "#"),
		strings.HasPrefix(line, "!"),
		strings.HasPrefix(line, "//"),
		strings.HasPrefix(line, "["),
		strings.HasPrefix(line, "@@"):
		return "", "", false
	}

	fields := strings.Fields(line)
	if len(fields) >= 2 && net.ParseIP(fields[0]) != nil {
		line = fields[len(fields)-1]
	}

	if strings.HasPrefix(line, "||") {
		line = strings.TrimPrefix(line, "||")
		line = strings.TrimSuffix(line, "^")
		line = strings.TrimPrefix(line, ".")
		line = strings.TrimSpace(line)
		if line == "" {
			return "", "", false
		}
		return line, models.RuleTypeNamespace, true
	}

	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		if parsedURL, err := neturl.Parse(line); err == nil && parsedURL.Hostname() != "" {
			return parsedURL.Hostname(), models.RuleTypeNamespace, true
		}
	}

	if strings.HasPrefix(line, "regexp:") {
		line = strings.TrimSpace(strings.TrimPrefix(line, "regexp:"))
		if line == "" {
			return "", "", false
		}
		return line, models.RuleTypeRegEx, true
	}

	if prefix, value, ok := strings.Cut(line, ","); ok {
		switch strings.ToUpper(strings.TrimSpace(prefix)) {
		case "DOMAIN":
			value = strings.TrimSpace(value)
			if value == "" {
				return "", "", false
			}
			return value, models.RuleTypeDomain, true
		case "DOMAIN-SUFFIX", "HOST-SUFFIX":
			value = strings.TrimSpace(value)
			if value == "" {
				return "", "", false
			}
			return value, models.RuleTypeNamespace, true
		case "DOMAIN-KEYWORD":
			value = strings.TrimSpace(value)
			if value == "" {
				return "", "", false
			}
			return "*" + value + "*", models.RuleTypeWildcard, true
		case "IP-CIDR", "IP-CIDR6":
			value = strings.TrimSpace(value)
			if _, ipNet, err := net.ParseCIDR(value); err == nil {
				if ipNet.IP.To4() != nil {
					return value, models.RuleTypeSubnet, true
				}
				return value, models.RuleTypeSubnet6, true
			}
			return "", "", false
		}
	}

	if _, ipNet, err := net.ParseCIDR(line); err == nil {
		if ipNet.IP.To4() != nil {
			return line, models.RuleTypeSubnet, true
		}
		return line, models.RuleTypeSubnet6, true
	}

	if strings.ContainsAny(line, "*?") {
		return line, models.RuleTypeWildcard, true
	}

	line = strings.TrimPrefix(line, ".")
	line = strings.TrimSpace(line)
	if line == "" {
		return "", "", false
	}

	return line, models.RuleTypeNamespace, true
}
