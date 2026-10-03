// Package iprange normalizes access-policy ranges before validating their scope.
package iprange

import (
	"fmt"
	"net/netip"
)

func Parse(value string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("expected an IP address or CIDR")
		}
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), nil
	}
	if prefix.Addr().Is4In6() {
		if prefix.Bits() < 96 {
			return netip.Prefix{}, fmt.Errorf("mapped IPv4 prefix is too broad")
		}
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	if prefix.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("trust-all/allow-all CIDR is not permitted")
	}
	return prefix.Masked(), nil
}
