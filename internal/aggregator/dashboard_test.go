package aggregator

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
)

func TestDashboardUsesExistingRollingCounters(t *testing.T) {
	a := New(limits())
	now := time.Unix(1_800_000_000, 0)
	a.Observe(request("shop", "192.0.2.1", "/a", 200), false, now)
	a.Observe(request("shop", "192.0.2.1", "/missing", 404), false, now)
	a.Observe(request("blog", "192.0.2.1", "/", 200), false, now)
	a.Observe(request("api", "192.0.2.2", "/private", 301), true, now)
	view := a.Dashboard(time.Second, now, 10)
	if view.Requests != 4 || view.StatusFamilies[2] != 2 || view.Statuses[404] != 1 || view.Statuses[301] != 1 || view.ActiveIPs != 1 || len(view.Sites) != 3 {
		t.Fatalf("view=%+v", view)
	}
	if view.Sites[0].SiteID != "api" || view.Sites[0].Requests != 1 || view.Sites[0].ActiveIPs != 0 {
		t.Fatalf("allowlisted site counters=%+v", view.Sites[0])
	}
	if len(view.TopIPs) != 1 || view.TopIPs[0].IP != netip.MustParseAddr("192.0.2.1") || view.TopIPs[0].NotFound != 1 || view.TopIPs[0].Unique404Paths != 1 {
		t.Fatalf("top IPs=%+v", view.TopIPs)
	}
	if got := view.TopIPs[0].SiteIDs; len(got) != 2 || got[0] != "blog" || got[1] != "shop" {
		t.Fatalf("aggregate IP sites=%v", got)
	}
}

func TestDashboardBoundedDuringTenThousandRequestBurst(t *testing.T) {
	settings := config.AggregationConfig{MaxActiveRecords: 128, MaxPathsPerIP: 8, Max404PathsPerIP: 8, MaxUserAgentsPerIP: 2, MaxQueriesPerIP: 4, MaxValueBytes: 64}
	a := New(settings)
	now := time.Unix(1_800_000_000, 0)
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for i := 0; i < 20; i++ {
			_ = a.Dashboard(time.Minute, now, 10)
		}
	}()
	for i := 0; i < 10000; i++ {
		ip := netip.AddrFrom4([4]byte{198, 51, byte(i / 256), byte(i % 256)})
		event := request("shop", ip.String(), fmt.Sprintf("/probe/%d", i), 404)
		a.Observe(event, false, now)
	}
	workers.Wait()
	view := a.Dashboard(time.Minute, now, 10)
	if view.Requests != 10000 || view.Statuses[404] != 10000 || view.WindowDropped == 0 || len(view.TopIPs) > 10 || view.ActiveIPs > settings.MaxActiveRecords/2 {
		t.Fatalf("unbounded or incorrect burst view: requests=%d status404=%d dropped=%d top=%d active=%d", view.Requests, view.Statuses[404], view.WindowDropped, len(view.TopIPs), view.ActiveIPs)
	}
}

func TestDashboardBoundsTopIPsAndLabelsDrops(t *testing.T) {
	a := New(limits())
	now := time.Unix(1_800_000_000, 0)
	for i := 1; i <= 3; i++ {
		a.Observe(request("shop", netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String(), "/", 404), false, now)
	}
	view := a.Dashboard(time.Second, now, 1)
	if len(view.TopIPs) != 1 || view.WindowDropped != 1 || view.Requests != 3 {
		t.Fatalf("bounded view=%+v", view)
	}
}

func TestDashboardMethodStatusCrossTotals(t *testing.T) {
	a := New(limits())
	now := time.Unix(1_800_000_000, 0)
	for _, entry := range []struct {
		method string
		status int
	}{{"GET", 200}, {"GET", 404}, {"PATCH", 403}, {"PATCH", 500}, {"PATCH", 301}} {
		event := request("shop", "192.0.2.1", "/probe", entry.status)
		event.Method = entry.method
		a.Observe(event, false, now)
	}
	view := a.Dashboard(time.Second, now, 10)
	if view.MethodHTTP["GET"] != (MethodHTTP{Requests: 2, Status2xx: 1, Status404: 1}) || view.MethodHTTP["PATCH"] != (MethodHTTP{Requests: 3, Status301: 1, Status403: 1, Status5xx: 1}) || view.Sites[0].MethodHTTP["PATCH"].Status5xx != 1 {
		t.Fatalf("method/status cross totals: %+v", view.MethodHTTP)
	}
}
