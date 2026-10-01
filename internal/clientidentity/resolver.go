// Package clientidentity resolves client IPs only through configured trusted
// proxies, then checks the resulting address against IP/CIDR allowlists.
package clientidentity

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

const maxProxyHops = 32

type Resolver struct {
	header  string
	trusted []netip.Prefix
	allowed []netip.Prefix
}

func New(cfg config.Config) (*Resolver, error) {
	resolver := &Resolver{header: cfg.ClientIP.Header}
	if resolver.header == "" {
		resolver.header = "x-forwarded-for"
	}
	switch resolver.header {
	case "x-forwarded-for", "cf-connecting-ip", "x-real-ip":
	default:
		return nil, fmt.Errorf("unsupported client IP header %q", resolver.header)
	}
	for _, value := range cfg.ClientIP.TrustedProxies {
		prefix, err := parseRange(value)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", value, err)
		}
		resolver.trusted = append(resolver.trusted, prefix)
	}
	for _, value := range cfg.Allowlist {
		prefix, err := parseRange(value)
		if err != nil {
			return nil, fmt.Errorf("allowlist %q: %w", value, err)
		}
		resolver.allowed = append(resolver.allowed, prefix)
	}
	return resolver, nil
}

// Resolve returns an event with canonical client identity and whether it is
// allowlisted. Malformed or missing forwarding data falls back to the peer.
func (r *Resolver) Resolve(event model.RequestEvent) (model.RequestEvent, bool) {
	peer := event.PeerIP.Unmap()
	if !peer.IsValid() {
		peer = event.ClientIP.Unmap()
	}
	client := peer
	if contains(r.trusted, peer) {
		switch r.header {
		case "x-forwarded-for":
			client = r.fromXForwardedFor(peer, event.ForwardedFor)
		case "cf-connecting-ip":
			client = singleForwarded(peer, event.CFConnectingIP)
		case "x-real-ip":
			client = singleForwarded(peer, event.XRealIP)
		}
	}
	event.ClientIP = client
	return event, contains(r.allowed, client)
}

func (r *Resolver) fromXForwardedFor(peer netip.Addr, header string) netip.Addr {
	if header == "" || strings.Count(header, ",") >= maxProxyHops {
		return peer
	}
	parts := strings.Split(header, ",")
	addresses := make([]netip.Addr, 0, len(parts))
	for _, part := range parts {
		addr, err := netip.ParseAddr(strings.TrimSpace(part))
		if err != nil {
			return peer
		}
		addresses = append(addresses, addr.Unmap())
	}
	current := peer
	for i := len(addresses) - 1; i >= 0 && contains(r.trusted, current); i-- {
		current = addresses[i]
	}
	return current
}

func singleForwarded(peer netip.Addr, header string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(header))
	if err != nil {
		return peer
	}
	return addr.Unmap()
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func parseRange(value string) (netip.Prefix, error) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		if prefix.Bits() == 0 {
			return netip.Prefix{}, fmt.Errorf("trust-all/allow-all CIDR is not permitted")
		}
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return netip.Prefix{}, fmt.Errorf("mapped IPv4 prefix is too broad")
			}
			return netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked(), nil
		}
		return prefix.Masked(), nil
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}
