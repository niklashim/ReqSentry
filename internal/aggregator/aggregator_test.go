package aggregator

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

func limits() config.AggregationConfig {
	return config.AggregationConfig{
		MaxActiveRecords: 4, MaxPathsPerIP: 2, Max404PathsPerIP: 2,
		MaxUserAgentsPerIP: 1, MaxQueriesPerIP: 1, MaxValueBytes: 64,
	}
}

func request(site, ip, path string, status int) model.RequestEvent {
	return model.RequestEvent{SiteID: site, ClientIP: netip.MustParseAddr(ip), Method: "GET", Path: path, Status: status}
}

func TestRollingWindowsAndMultiSiteTotals(t *testing.T) {
	rollup := New(limits())
	start := time.Unix(1_800_000_000, 0)
	ip := netip.MustParseAddr("2001:db8::1")
	first := request("one", ip.String(), "/missing", 404)
	bytes := int64(10)
	requestTime := 5 * time.Millisecond
	first.Bytes = &bytes
	first.RequestTime = &requestTime
	rollup.Observe(first, false, start)
	rollup.Observe(first, false, start)
	rollup.Observe(request("one", ip.String(), "/ok", 200), false, start.Add(9*time.Second))
	rollup.Observe(request("two", ip.String(), "/redirect", 301), false, start.Add(10*time.Second))
	rollup.Observe(request("two", "192.0.2.9", "/allowed", 200), true, start.Add(10*time.Second))

	global, ok := rollup.Snapshot("", ip, 30*time.Second, start.Add(10*time.Second))
	if !ok || global.Requests != 4 || global.PeakRPS != 2 || global.StatusFamilies[4] != 2 || global.ImportantStatuses[404] != 2 || global.ImportantStatuses[301] != 1 {
		t.Fatalf("global 30s snapshot: %+v, ok=%v", global, ok)
	}
	if global.BytesTotal != 20 || global.BytesSamples != 2 || global.RequestTimeNanos != uint64(10*time.Millisecond) || global.RequestTimeSamples != 2 {
		t.Fatalf("optional measurements: %+v", global)
	}
	if global.UniquePaths != 2 || !global.Saturation.Paths {
		t.Fatalf("expected bounded path diversity: %+v", global)
	}
	one, ok := rollup.Snapshot("one", ip, 10*time.Second, start.Add(10*time.Second))
	if !ok || one.Requests != 1 || one.PeakRPS != 1 {
		t.Fatalf("site one 10s snapshot: %+v", one)
	}
	lastSecond, ok := rollup.Snapshot("", ip, time.Second, start.Add(10*time.Second))
	if !ok || lastSecond.Requests != 1 {
		t.Fatalf("1s snapshot: %+v", lastSecond)
	}
	minute, ok := rollup.Snapshot("", ip, 60*time.Second, start.Add(10*time.Second))
	if !ok || minute.Requests != 4 {
		t.Fatalf("60s snapshot: %+v", minute)
	}
	if total := rollup.TotalRequests(30*time.Second, start.Add(10*time.Second)); total != 5 {
		t.Fatalf("server total should include allowlisted request, got %d", total)
	}
	if _, ok := rollup.Snapshot("two", netip.MustParseAddr("192.0.2.9"), 30*time.Second, start.Add(10*time.Second)); ok {
		t.Fatal("allowlisted IP entered detection statistics")
	}
}

func TestCapsSaturationAndExpiry(t *testing.T) {
	rollup := New(limits())
	start := time.Unix(1_800_000_000, 0)
	ip := "192.0.2.1"
	for i, path := range []string{"/a", "/b", "/c"} {
		event := request("one", ip, path, 404)
		ua := strings.Repeat("agent", i+1)
		event.UserAgent = &ua
		event.Query = "token=secret" + string(rune('0'+i))
		if !rollup.Observe(event, false, start.Add(time.Duration(i)*time.Second)) {
			t.Fatal("existing IP was dropped")
		}
	}
	snapshot, ok := rollup.Snapshot("one", netip.MustParseAddr(ip), 30*time.Second, start.Add(2*time.Second))
	if !ok || snapshot.UniquePaths != 2 || snapshot.Unique404Paths != 2 || snapshot.UserAgents != 1 || snapshot.QueryPatterns != 1 {
		t.Fatalf("limits not applied: %+v", snapshot)
	}
	if !snapshot.Saturation.Paths || !snapshot.Saturation.MissingPaths || !snapshot.Saturation.UserAgents {
		t.Fatalf("saturation not reported: %+v", snapshot.Saturation)
	}
	for pattern := range rollup.records[key{site: "one", ip: netip.MustParseAddr(ip)}].queries {
		if strings.Contains(pattern, "secret") {
			t.Fatalf("raw query value retained: %q", pattern)
		}
	}
	rollup.Observe(request("one", "192.0.2.2", "/other", 200), false, start.Add(3*time.Second))
	if rollup.Observe(request("one", "192.0.2.3", "/drop", 200), false, start.Add(3*time.Second)) {
		t.Fatal("record cap did not drop a new IP")
	}
	if rollup.Metrics().DroppedEvents != 1 || rollup.Metrics().ActiveRecords != 4 {
		t.Fatalf("record metrics: %+v", rollup.Metrics())
	}
	rollup.Prune(start.Add(64 * time.Second))
	if rollup.Metrics().ActiveRecords != 0 {
		t.Fatalf("expired records retained: %+v", rollup.Metrics())
	}
	if !rollup.Observe(request("one", "192.0.2.3", "/new", 200), false, start.Add(64*time.Second)) {
		t.Fatal("expired record capacity was not reused")
	}
	if total := rollup.TotalRequests(60*time.Second, start.Add(64*time.Second)); total != 1 {
		t.Fatalf("old server totals did not expire, got %d", total)
	}
}

func TestDegradedModeKeepsBasicCountersUnderLoad(t *testing.T) {
	rollup := New(limits())
	now := time.Unix(1_800_000_000, 0)
	if !rollup.SetDegraded(true) {
		t.Fatal("failed to enter degraded mode")
	}
	for i := 0; i < 20000; i++ {
		event := request("one", "192.0.2.1", "/dynamic/long/path", 404)
		event.Query = strings.Repeat("q", 4096)
		if !rollup.Observe(event, false, now) {
			t.Fatalf("request %d dropped", i)
		}
	}
	snapshot, ok := rollup.Snapshot("one", netip.MustParseAddr("192.0.2.1"), time.Second, now)
	if !ok || snapshot.Requests != 20000 || snapshot.ImportantStatuses[404] != 20000 || snapshot.Methods["GET"] != 20000 || !snapshot.Saturation.Degraded {
		t.Fatalf("basic counters: %+v", snapshot)
	}
	if snapshot.UniquePaths != 0 || snapshot.QueryPatterns != 0 || rollup.Metrics().ActiveRecords != 2 {
		t.Fatalf("rich tracking continued: %+v metrics=%+v", snapshot, rollup.Metrics())
	}
	if !rollup.SetDegraded(false) {
		t.Fatal("failed to recover")
	}
	rollup.Observe(request("one", "192.0.2.1", "/after", 200), false, now.Add(time.Second))
	recovered, _ := rollup.Snapshot("one", netip.MustParseAddr("192.0.2.1"), time.Second, now.Add(time.Second))
	if recovered.Saturation.Degraded || recovered.UniquePaths != 1 {
		t.Fatalf("recovery: %+v", recovered)
	}
}

func TestExpiredPathCapacityIsReusedForActiveIP(t *testing.T) {
	rollup := New(limits())
	start := time.Unix(1_800_000_000, 0)
	ip := netip.MustParseAddr("192.0.2.4")
	rollup.Observe(request("one", ip.String(), "/old", 404), false, start)
	rollup.Observe(request("one", ip.String(), "/keep", 404), false, start.Add(time.Second))
	rollup.Observe(request("one", ip.String(), "/keep", 404), false, start.Add(30*time.Second))
	rollup.Observe(request("one", ip.String(), "/new", 404), false, start.Add(61*time.Second))
	snapshot, ok := rollup.Snapshot("one", ip, 60*time.Second, start.Add(61*time.Second))
	if !ok || snapshot.UniquePaths != 2 || snapshot.Saturation.Paths || snapshot.Unique404Paths != 2 {
		t.Fatalf("expired path cap was not reused: %+v", snapshot)
	}
}
