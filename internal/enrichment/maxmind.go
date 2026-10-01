// Package enrichment reads local MMDB files only when an incident is emitted.
package enrichment

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sync"

	"github.com/oschwald/maxminddb-golang/v2"
)

var databaseNames = []string{
	"GeoIP2-Enterprise.mmdb", "GeoIP2-ISP.mmdb", "GeoLite2-ASN.mmdb",
	"GeoIP2-City.mmdb", "GeoLite2-City.mmdb", "GeoIP2-Country.mmdb", "GeoLite2-Country.mmdb",
}

var ErrNoDatabase = errors.New("no supported MaxMind MMDB file found")

type Result struct {
	Available       bool
	Found           bool
	ASN             *uint32
	ASNOrganization string
	ISP             string
	NetworkType     string
	Country         string
}

type Manager struct {
	directory string
	mu        sync.RWMutex
	readers   []*maxminddb.Reader
}

func New(directory string) (*Manager, error) {
	m := &Manager{directory: directory}
	return m, m.Reload()
}

// Reload validates replacement files before swapping readers. Existing
// lookups finish before old memory mappings close.
func (m *Manager) Reload() error {
	var next []*maxminddb.Reader
	closeNext := func() {
		for _, reader := range next {
			_ = reader.Close()
		}
	}
	for _, name := range databaseNames {
		path := filepath.Join(m.directory, name)
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			closeNext()
			return fmt.Errorf("stat MaxMind database %s: %w", name, err)
		}
		reader, err := maxminddb.Open(path)
		if err != nil {
			closeNext()
			return fmt.Errorf("open MaxMind database %s: %w", name, err)
		}
		if err := reader.Verify(); err != nil {
			_ = reader.Close()
			closeNext()
			return fmt.Errorf("verify MaxMind database %s: %w", name, err)
		}
		next = append(next, reader)
	}
	if len(next) == 0 {
		return ErrNoDatabase
	}
	m.mu.Lock()
	old := m.readers
	m.readers = next
	for _, reader := range old {
		_ = reader.Close()
	}
	m.mu.Unlock()
	return nil
}

func (m *Manager) Lookup(ip netip.Addr) (Result, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := Result{Available: len(m.readers) > 0}
	if !ip.IsValid() || !result.Available {
		return result, nil
	}
	for _, reader := range m.readers {
		found := reader.Lookup(ip.Unmap())
		if err := found.Err(); err != nil {
			return result, err
		}
		if !found.Found() {
			continue
		}
		var record struct {
			ASN             uint32 `maxminddb:"autonomous_system_number"`
			ASNOrganization string `maxminddb:"autonomous_system_organization"`
			ISP             string `maxminddb:"isp"`
			Country         struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
			Traits struct {
				ASN             uint32 `maxminddb:"autonomous_system_number"`
				ASNOrganization string `maxminddb:"autonomous_system_organization"`
				ISP             string `maxminddb:"isp"`
				UserType        string `maxminddb:"user_type"`
				ConnectionType  string `maxminddb:"connection_type"`
			} `maxminddb:"traits"`
		}
		if err := found.Decode(&record); err != nil {
			return result, err
		}
		result.Found = true
		asn := record.Traits.ASN
		if asn == 0 {
			asn = record.ASN
		}
		if asn != 0 && result.ASN == nil {
			result.ASN = &asn
		}
		if result.ASNOrganization == "" {
			result.ASNOrganization = firstNonempty(record.Traits.ASNOrganization, record.ASNOrganization)
		}
		if result.ISP == "" {
			result.ISP = firstNonempty(record.Traits.ISP, record.ISP)
		}
		if result.NetworkType == "" {
			result.NetworkType = firstNonempty(record.Traits.UserType, record.Traits.ConnectionType)
		}
		if result.Country == "" {
			result.Country = record.Country.ISOCode
		}
	}
	return result, nil
}

func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, reader := range m.readers {
		errs = append(errs, reader.Close())
	}
	m.readers = nil
	return errors.Join(errs...)
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
