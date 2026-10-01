package enrichment

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/oschwald/maxminddb-golang/v2"
)

func TestLocalEnterpriseIPv4IPv6AndMissingData(t *testing.T) {
	manager, err := New("testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	first, err := manager.Lookup(netip.MustParseAddr("74.209.24.0"))
	if err != nil || !first.Available || !first.Found || first.ASN == nil || *first.ASN != 14671 || first.ASNOrganization != "FairPoint Communications" || first.NetworkType != "residential" || first.Country != "US" {
		t.Fatalf("IPv4 enrichment: %+v %v", first, err)
	}
	second, err := manager.Lookup(netip.MustParseAddr("149.101.100.0"))
	if err != nil || second.ISP != "Verizon Wireless" || second.ASN == nil || *second.ASN != 6167 {
		t.Fatalf("ISP enrichment: %+v %v", second, err)
	}
	reader, err := maxminddb.Open(filepath.Join("testdata", "GeoIP2-Enterprise.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var ipv6 netip.Addr
	for record := range reader.Networks() {
		address := record.Prefix().Addr()
		if record.Found() && address.Is6() && !address.Is4In6() {
			ipv6 = address
			break
		}
	}
	if !ipv6.IsValid() {
		t.Fatal("fixture has no IPv6 record")
	}
	v6, err := manager.Lookup(ipv6)
	if err != nil || !v6.Available || !v6.Found {
		t.Fatalf("IPv6 enrichment for %s: %+v %v", ipv6, v6, err)
	}
	missing, err := manager.Lookup(netip.MustParseAddr("192.0.2.1"))
	if err != nil || !missing.Available || missing.Found {
		t.Fatalf("missing record confused with missing database: %+v %v", missing, err)
	}
}

func TestReloadRetainsReaderOnInvalidReplacement(t *testing.T) {
	dir := t.TempDir()
	data, err := os.ReadFile(filepath.Join("testdata", "GeoIP2-Enterprise.mmdb"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "GeoIP2-Enterprise.mmdb")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	manager, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("invalid MMDB"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(); err == nil {
		t.Fatal("invalid replacement was accepted")
	}
	got, err := manager.Lookup(netip.MustParseAddr("74.209.24.0"))
	if err != nil || !got.Found {
		t.Fatalf("old validated reader was lost: %+v %v", got, err)
	}
	if err := os.Rename(path+".old", path); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(); err != nil {
		t.Fatal(err)
	}
}

func TestMissingDatabaseLeavesLookupUnavailable(t *testing.T) {
	manager, err := New(t.TempDir())
	if !errors.Is(err, ErrNoDatabase) {
		t.Fatalf("missing database error: %v", err)
	}
	defer manager.Close()
	result, err := manager.Lookup(netip.MustParseAddr("2001:db8::1"))
	if err != nil || result.Available || result.Found {
		t.Fatalf("missing database lookup: %+v %v", result, err)
	}
}
