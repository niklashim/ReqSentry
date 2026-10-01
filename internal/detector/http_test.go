package detector

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/phpfpm"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
)

func testAggregator() *aggregator.Aggregator {
	return aggregator.New(config.AggregationConfig{
		MaxActiveRecords: 10, MaxPathsPerIP: 100, Max404PathsPerIP: 100,
		MaxUserAgentsPerIP: 10, MaxQueriesPerIP: 100, MaxValueBytes: 256,
	})
}

func addEvent(a *aggregator.Aggregator, at time.Time, path, query string, status int) {
	a.Observe(model.RequestEvent{
		SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"),
		Method: "GET", Path: path, Query: query, Status: status,
	}, false, at)
}

func snapshot(a *aggregator.Aggregator, at time.Time) aggregator.Snapshot {
	result, _ := a.Snapshot("shop", netip.MustParseAddr("192.0.2.1"), 30*time.Second, at)
	return result
}

func hasSignal(signals []model.Signal, code string) bool {
	for _, value := range signals {
		if value.Code == code {
			return true
		}
	}
	return false
}

func TestEnumerationVsRepeatedMissingAsset(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	sequence := testAggregator()
	for i := 0; i < 30; i++ {
		addEvent(sequence, start, fmt.Sprintf("/users/%d", 10000+i), "", 404)
	}
	signals := HTTP(snapshot(sequence, start))
	for _, code := range []string{"HIGH_404_RATE", "HIGH_404_DIVERSITY", "PATH_ENUMERATION"} {
		if !hasSignal(signals, code) {
			t.Fatalf("missing %s in %+v", code, signals)
		}
	}
	if got := NormalizePath("/users/18291/orders/42"); got != "/users/{NUMBER}/orders/{NUMBER}" {
		t.Fatalf("normalized path: %s", got)
	}
	repeated := testAggregator()
	for i := 0; i < 500; i++ {
		addEvent(repeated, start, "/old-logo.png", "", 404)
	}
	signals = HTTP(snapshot(repeated, start))
	if !hasSignal(signals, "HIGH_404_RATE") || hasSignal(signals, "HIGH_404_DIVERSITY") || hasSignal(signals, "PATH_ENUMERATION") {
		t.Fatalf("repeated missing asset treated as enumeration: %+v", signals)
	}
}

func TestEncodedPathAndQueryNormalizationCollisions(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	a := testAggregator()
	for _, path := range []string{"/users/123", "/users/%31%32%33", "/users/%31%323"} {
		addEvent(a, start, path, "", 404)
	}
	for _, query := range []string{"id=12", "%69d=%31%32", "id=1%32"} {
		addEvent(a, start, "/product", query, 404)
	}
	got := snapshot(a, start)
	if got.Unique404Paths != 2 || got.UniqueQueryValues != 1 || got.QueryPatterns != 1 {
		t.Fatalf("encoding variants inflated diversity: %+v", got)
	}
	if NormalizePath("/users/%31%32%33") != "/users/{NUMBER}" || aggregator.CanonicalPath("/a%2fb") != "/a%2Fb" {
		t.Fatal("reserved and unreserved URL bytes were normalized incorrectly")
	}
}

func TestThresholdOverrideChangesSignal(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	rollup := testAggregator()
	for i := 0; i < 25; i++ {
		addEvent(rollup, start, "/missing", "", 404)
	}
	for i := 0; i < 5; i++ {
		addEvent(rollup, start, "/ok", "", 200)
	}
	base := snapshot(rollup, start)
	if !hasSignal(HTTP(base), "HIGH_404_RATE") {
		t.Fatal("default high 404 signal missing")
	}
	rules := config.DefaultDetectionConfig()
	rules.Thresholds["high_404_ratio"] = 0.95
	if hasSignal(HTTPWithRules(base, rules), "HIGH_404_RATE") {
		t.Fatal("configured 404 threshold was ignored")
	}
}

func TestQueryEnumerationAndSupportingRedirects(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	queries := testAggregator()
	for i := 0; i < 12; i++ {
		addEvent(queries, start, "/product", fmt.Sprintf("id=%d", 10000+i), 404)
	}
	signals := HTTP(snapshot(queries, start))
	if !hasSignal(signals, "QUERY_ENUMERATION") {
		t.Fatalf("query enumeration not found: %+v", signals)
	}
	redirects := testAggregator()
	for i := 0; i < 30; i++ {
		addEvent(redirects, start, "/old", "", 301)
	}
	signals = HTTP(snapshot(redirects, start))
	if !hasSignal(signals, "HIGH_REDIRECT_RATIO") {
		t.Fatalf("redirect ratio missing: %+v", signals)
	}
	for _, value := range signals {
		if value.Code == "HIGH_REDIRECT_RATIO" && value.Strength != model.SignalSupporting {
			t.Fatalf("redirect ratio should be supporting: %+v", value)
		}
	}
}

func TestRedirectFollowEvidenceRequiresLocation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a := testAggregator()
	for i := 0; i < 60; i++ {
		location := "/new?id=12"
		a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET", Path: "/old", Status: 301, Location: &location}, false, now)
		if i < 20 {
			a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET", Path: "/new", Query: "%69d=%31%32", Status: 200}, false, now)
		}
	}
	s := snapshot(a, now)
	if s.RedirectKnown != 60 || s.RedirectFollows != 20 {
		t.Fatalf("redirect follow count: %+v", s)
	}
	var evidence map[string]any
	for _, signal := range HTTP(s) {
		if signal.Code == "HIGH_REDIRECT_RATIO" {
			evidence = signal.Evidence
		}
	}
	if evidence == nil || evidence["follow_behavior"] != "observed" || evidence["followed_targets"] != uint64(20) {
		t.Fatalf("redirect follow evidence: %#v", evidence)
	}
	missing := testAggregator()
	for i := 0; i < 20; i++ {
		addEvent(missing, now, "/old", "", 301)
	}
	for _, signal := range HTTP(snapshot(missing, now)) {
		if signal.Code == "HIGH_REDIRECT_RATIO" && signal.Evidence["follow_behavior"] != "unavailable" {
			t.Fatalf("missing Location was assessed: %+v", signal)
		}
	}
}

func TestBurstAndSustainedRateRemainDistinct(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	burst := testAggregator()
	for i := 0; i < 300; i++ {
		addEvent(burst, start, "/", "", 200)
	}
	signals := HTTP(snapshot(burst, start))
	if !hasSignal(signals, "HIGH_REQUEST_RATE") || !hasSignal(signals, "HIGH_BURST_RATE") || hasSignal(signals, "SUSTAINED_HIGH_RATE") {
		t.Fatalf("burst rate signals: %+v", signals)
	}
	sustained := testAggregator()
	for second := 0; second < 30; second++ {
		for i := 0; i < 10; i++ {
			addEvent(sustained, start.Add(time.Duration(second)*time.Second), "/", "", 200)
		}
	}
	signals = HTTP(snapshot(sustained, start.Add(29*time.Second)))
	if !hasSignal(signals, "SUSTAINED_HIGH_RATE") || hasSignal(signals, "HIGH_BURST_RATE") {
		t.Fatalf("sustained rate signals: %+v", signals)
	}
}

func TestMethod404AndUserAgentSignalsAreContextual(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	methodScan := testAggregator()
	for i := 0; i < 12; i++ {
		methodScan.Observe(model.RequestEvent{
			SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"),
			Method: "PATCH", Path: fmt.Sprintf("/unknown/%d", i), Status: 404,
		}, false, start)
	}
	if !hasSignal(HTTP(snapshot(methodScan, start)), "METHOD_404_SCAN") {
		t.Fatal("method/status scan was not detected")
	}
	api := testAggregator()
	for i := 0; i < 20; i++ {
		ua := []string{"Mozilla/5.0", "api-client/1", "python-requests/2", "curl/8"}[i%4]
		api.Observe(model.RequestEvent{
			SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"),
			Method: "OPTIONS", Path: "/api/resource", Status: 200, UserAgent: &ua,
		}, false, start)
	}
	signals := HTTP(snapshot(api, start))
	if hasSignal(signals, "METHOD_404_SCAN") || !hasSignal(signals, "USER_AGENT_ROTATION") || !hasSignal(signals, "AUTOMATED_USER_AGENT") {
		t.Fatalf("API method or UA signals incorrect: %+v", signals)
	}
	apiSummary := snapshot(api, start)
	if apiSummary.UserAgentSwitches != 19 || apiSummary.UserAgentCounts["api-client/1"] != 5 || apiSummary.PrimaryUserAgent == "" {
		t.Fatalf("User-Agent counts or rotation summary: %+v", apiSummary)
	}
	for _, value := range signals {
		if value.Code == "AUTOMATED_USER_AGENT" && value.Strength != model.SignalSupporting {
			t.Fatal("User-Agent should remain supporting evidence")
		}
	}
	mixed := testAggregator()
	for i := 0; i < 20; i++ {
		mixed.Observe(model.RequestEvent{SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET", Path: fmt.Sprintf("/missing/%d", i), Status: 404}, false, start)
	}
	for i := 0; i < 10; i++ {
		mixed.Observe(model.RequestEvent{SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "PATCH", Path: "/same", Status: 404}, false, start)
	}
	if hasSignal(HTTP(snapshot(mixed, start)), "METHOD_404_SCAN") {
		t.Fatal("unrelated GET diversity made one repeated PATCH path look like a method scan")
	}
}

func TestImpactRequiresAlignedHealthEvidence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	cpu := 90.0
	queue := int64(2)
	global := aggregator.Snapshot{
		At: now, SiteID: "", Window: 30 * time.Second, Requests: 120,
		ImportantStatuses: map[int]uint64{404: 90}, Unique404Paths: 50,
		RequestTimeSamples: 12, RequestTimeNanos: uint64(12 * time.Second),
	}
	health := serverhealth.Snapshot{Timestamp: now, CPUPercent: &cpu}
	pools := []phpfpm.State{{Name: "www", SampledAt: now, Stats: &phpfpm.Stats{ListenQueue: &queue}}}
	signals := Impact(global, 240, 4, health, pools)
	for _, code := range []string{"CROSS_SITE_SCAN", "HIGH_TRAFFIC_SHARE", "CPU_SPIKE_CONTRIBUTOR", "PHP_FPM_SATURATION_CONTRIBUTOR", "HIGH_REQUEST_COST"} {
		if !hasSignal(signals, code) {
			t.Fatalf("missing %s from %+v", code, signals)
		}
	}
	health.Timestamp = now.Add(-time.Minute)
	pools[0].Stale = true
	signals = Impact(global, 240, 4, health, pools)
	if hasSignal(signals, "CPU_SPIKE_CONTRIBUTOR") || hasSignal(signals, "PHP_FPM_SATURATION_CONTRIBUTOR") {
		t.Fatalf("stale health contributed to incident: %+v", signals)
	}
}

func TestCrossSiteScanBelowIndividualSiteThresholds(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a := testAggregator()
	ip := netip.MustParseAddr("2001:db8::2")
	for site := 0; site < 3; site++ {
		name := fmt.Sprintf("site-%d", site)
		for i := 0; i < 20; i++ {
			a.Observe(model.RequestEvent{SiteID: name, ClientIP: ip, Method: "GET", Path: fmt.Sprintf("/missing/%d/%d", site, i), Status: 404}, false, now)
		}
		siteSnapshot, ok := a.Snapshot(name, ip, 30*time.Second, now)
		if !ok || hasSignal(HTTP(siteSnapshot), "HIGH_404_RATE") {
			t.Fatalf("single site crossed scan threshold: %+v", siteSnapshot)
		}
	}
	global, ok := a.Snapshot("", ip, 30*time.Second, now)
	if !ok || a.SiteCount(ip, 30*time.Second, now) != 3 || !hasSignal(Impact(global, a.TotalRequests(30*time.Second, now), 3, serverhealth.Snapshot{}, nil), "CROSS_SITE_SCAN") {
		t.Fatalf("spread-out scan was missed: %+v", global)
	}
}

func TestLowVolumeExpensiveRequests(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	a := testAggregator()
	ip := netip.MustParseAddr("192.0.2.9")
	cost := 900 * time.Millisecond
	for i := 0; i < 10; i++ {
		a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: ip, Method: "GET", Path: "/search", Status: 200, RequestTime: &cost}, false, now)
	}
	global, ok := a.Snapshot("", ip, 30*time.Second, now)
	if !ok || !hasSignal(Impact(global, 100, 1, serverhealth.Snapshot{}, nil), "HIGH_REQUEST_COST") {
		t.Fatalf("expensive low-volume traffic missed: %+v", global)
	}
}
