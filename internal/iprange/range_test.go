package iprange

import (
	"net/netip"
	"testing"
)

func TestEffectivePolicyScope(t *testing.T) {
	for _, value := range []string{"0.0.0.0/0", "::/0", "::ffff:0.0.0.0/96", "::ffff:192.0.2.1/95"} {
		if _, err := Parse(value); err == nil {
			t.Fatalf("accepted effective allow-all: %s", value)
		}
	}
	p, err := Parse("::ffff:192.0.2.99/120")
	if err != nil || p.String() != "192.0.2.0/24" || !p.Contains(netip.MustParseAddr("192.0.2.1")) || p.Contains(netip.MustParseAddr("198.51.100.1")) {
		t.Fatalf("mapped policy=%v %v", p, err)
	}
}
