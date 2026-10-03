package clientidentity

import (
	"net/netip"
	"testing"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

func event(peer, forwarded string) model.RequestEvent {
	addr := netip.MustParseAddr(peer)
	return model.RequestEvent{ClientIP: addr, LogIP: addr, PeerIP: addr, ForwardedFor: forwarded}
}

func TestTrustedProxyChainRejectsSpoofedLeftmostAddress(t *testing.T) {
	resolver, err := New(config.Config{ClientIP: config.ClientIPConfig{
		Header: "x-forwarded-for", TrustedProxies: []string{"10.0.0.0/8", "2001:db8:1::/48"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		peer, header, want string
	}{
		{"198.51.100.1", "1.2.3.4", "198.51.100.1"},
		{"10.0.0.2", "203.0.113.9, 10.0.0.1", "203.0.113.9"},
		{"10.0.0.2", "1.2.3.4, 198.51.100.9", "198.51.100.9"},
		{"10.0.0.2", "invalid, 10.0.0.1", "10.0.0.2"},
		{"2001:db8:1::2", "2001:db8:2::9, 2001:db8:1::1", "2001:db8:2::9"},
	}
	for _, tt := range tests {
		resolved, _ := resolver.Resolve(event(tt.peer, tt.header))
		if got := resolved.ClientIP.String(); got != tt.want {
			t.Errorf("peer=%s header=%q resolved=%s, want %s", tt.peer, tt.header, got, tt.want)
		}
	}
}

func TestSingleHeaderAndAllowlist(t *testing.T) {
	resolver, err := New(config.Config{
		ClientIP:  config.ClientIPConfig{Header: "cf-connecting-ip", TrustedProxies: []string{"2001:db8:1::/48"}},
		Allowlist: []string{"2001:db8:2::/48", "192.0.2.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	input := event("2001:db8:1::2", "spoofed")
	input.CFConnectingIP = "2001:db8:2::8"
	resolved, allowed := resolver.Resolve(input)
	if resolved.ClientIP.String() != "2001:db8:2::8" || !allowed {
		t.Fatalf("expected allowed IPv6 client, got %+v allowed=%v", resolved, allowed)
	}
	input.CFConnectingIP = "invalid"
	resolved, allowed = resolver.Resolve(input)
	if resolved.ClientIP != input.PeerIP || allowed {
		t.Fatalf("invalid header should use peer, got %+v allowed=%v", resolved, allowed)
	}
	resolved, allowed = resolver.Resolve(event("192.0.2.1", ""))
	if !allowed || resolved.ClientIP.String() != "192.0.2.1" {
		t.Fatalf("IPv4 allowlist failed: %+v allowed=%v", resolved, allowed)
	}
}

func TestResolverRejectsMappedAllowAllPolicies(t *testing.T) {
	for _, cfg := range []config.Config{
		{Allowlist: []string{"::ffff:0.0.0.0/96"}},
		{ClientIP: config.ClientIPConfig{TrustedProxies: []string{"::ffff:0.0.0.0/96"}}},
	} {
		if _, err := New(cfg); err == nil {
			t.Fatal("mapped allow-all policy accepted")
		}
	}
}
