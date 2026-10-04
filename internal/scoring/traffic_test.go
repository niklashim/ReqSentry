package scoring

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/detector"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/phpfpm"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
)

// These fixtures exercise observed behavior, not a claim that an IP belongs to
// a bot. In particular, shared exits and successful pagination must not become
// WOULD_BLOCK merely because the server is busy or the client is automated.
func TestDefaultTrafficDecisions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		count    int
		method   string
		status   int
		path     func(int) string
		query    func(int) string
		rotateUA bool
		pressure bool
		hosting  bool
		decision model.Decision
	}{
		{"browser", 40, "GET", 200, func(i int) string { return fmt.Sprintf("/page/%d", i) }, nil, false, false, false, model.DecisionNormal},
		{"hosting API pagination under pressure", 600, "GET", 200, func(int) string { return "/api/items" }, func(i int) string { return fmt.Sprintf("page=%d", i) }, false, true, true, model.DecisionSuspicious},
		{"shared residential NAT with many user agents", 600, "GET", 200, func(int) string { return "/" }, nil, true, true, false, model.DecisionWatch},
		{"healthy hosting crawler", 600, "GET", 200, func(i int) string { return fmt.Sprintf("/product/%d", i) }, nil, false, false, true, model.DecisionWatch},
		{"redirect migration", 600, "GET", 301, func(int) string { return "/old-page" }, nil, false, true, false, model.DecisionWatch},
		{"hosting API outage under load", 600, "GET", 503, func(int) string { return "/api/health" }, nil, true, true, true, model.DecisionSuspicious},
		{"hosting repeated missing asset under load", 600, "GET", 404, func(int) string { return "/old-logo.png" }, nil, true, true, true, model.DecisionSuspicious},
		{"numeric path scan", 600, "GET", 404, func(i int) string { return fmt.Sprintf("/users/%d", i) }, nil, false, false, false, model.DecisionWouldBlock},
		{"method scan", 600, "PATCH", 404, func(i int) string { return fmt.Sprintf("/unknown/resource-%d", i) }, nil, false, false, false, model.DecisionWouldBlock},
		{"hosting failed numeric query probing", 600, "GET", 404, func(int) string { return "/api/items" }, func(i int) string { return fmt.Sprintf("id=%d", i) }, false, false, true, model.DecisionSuspicious},
		{"ordinary sitemap fetches", 10, "GET", 200, func(int) string { return "/wp-sitemap.xml" }, nil, false, false, true, model.DecisionNormal},
		{"static asset burst", 600, "GET", 200, func(int) string { return "/wp-content/app.js" }, nil, false, false, false, model.DecisionWatch},
		{"residential sitemap flood", 600, "GET", 200, func(int) string { return "/wp-sitemap.xml" }, nil, false, false, false, model.DecisionSuspicious},
		{"hosting sitemap flood", 600, "GET", 200, func(int) string { return "/post-sitemap.xml" }, nil, false, false, true, model.DecisionWouldBlock},
		{"hosting XML-RPC flood", 600, "POST", 200, func(int) string { return "/xmlrpc.php" }, nil, false, false, true, model.DecisionWouldBlock},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{Server: config.ServerConfig{Name: "fixture"}, AccessFiles: []config.AccessFile{{Path: "/fixture/access.log", Site: "shop"}}, Database: config.DatabaseConfig{Path: "/fixture/state.db"}}
			if err := cfg.Validate(); err != nil {
				t.Fatal(err)
			}
			a := aggregator.New(cfg.Aggregation)
			at := time.Unix(1_800_000_000, 0)
			ip := netip.MustParseAddr("192.0.2.1")
			cost := 900 * time.Millisecond
			for i := 0; i < tc.count; i++ {
				ua := "curl/8"
				if tc.rotateUA {
					ua = []string{"Mozilla/5.0", "integration/1", "curl/8", "python-requests/2"}[i%4]
				}
				event := model.RequestEvent{ClientIP: ip, SiteID: "shop", Method: tc.method, Path: tc.path(i), Status: tc.status, UserAgent: &ua}
				if tc.query != nil {
					event.Query = tc.query(i)
				}
				if tc.pressure {
					event.RequestTime = &cost
				}
				a.Observe(event, false, at.Add(time.Duration(i%30)*time.Second))
			}
			end := at.Add(29 * time.Second)
			global, ok := a.Snapshot("", ip, 30*time.Second, end)
			if !ok {
				t.Fatal("missing traffic snapshot")
			}
			health := serverhealth.Snapshot{}
			var pools []phpfpm.State
			if tc.pressure {
				cpu, queue := 90.0, int64(3)
				health = serverhealth.Snapshot{Timestamp: end, CPUPercent: &cpu}
				pools = []phpfpm.State{{Name: "www", SampledAt: end, Stats: &phpfpm.Stats{ListenQueue: &queue}}}
			}
			signals := detector.HTTPWithRules(global, cfg.Detection)
			signals = append(signals, detector.ImpactWithRules(global, uint64(tc.count), 1, health, pools, cfg.Detection)...)
			if tc.hosting {
				signals = append(signals, model.Signal{Code: "HOSTING_NETWORK", Strength: model.SignalSupporting})
			}
			engine, err := New(cfg.Detection)
			if err != nil {
				t.Fatal(err)
			}
			incident := engine.Evaluate(Input{Server: "fixture", Snapshot: global, Signals: signals, AllRequests: uint64(tc.count), Health: health, PHPFPM: pools})
			t.Logf("score=%d decision=%s signals=%+v", incident.Score, incident.Decision, incident.Signals)
			if incident.Decision != tc.decision {
				t.Fatalf("expected %s, got %s (%d)", tc.decision, incident.Decision, incident.Score)
			}
		})
	}
}

func TestGoogleASNExclusionAndUnknownMetadata(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		asn                                *uint32
		available, found, optOut, excluded bool
	}{
		{"Google", asnNumber(15169), true, true, false, true},
		{"other hosting ASN", asnNumber(64512), true, true, false, false},
		{"unknown ASN", nil, true, true, false, false},
		{"unavailable data", asnNumber(15169), false, false, false, false},
		{"explicit opt out", asnNumber(15169), true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := config.DefaultDetectionConfig()
			if tc.optOut {
				rules.ExcludedASNs = []uint32{}
			}
			engine, err := New(rules)
			if err != nil {
				t.Fatal(err)
			}
			input := testInput(model.Signal{Code: "PATH_ENUMERATION", Strength: model.SignalStrong}, model.Signal{Code: "HIGH_404_DIVERSITY", Strength: model.SignalStrong}, model.Signal{Code: "HIGH_404_RATE", Strength: model.SignalSupporting}, model.Signal{Code: "HIGH_REQUEST_RATE", Strength: model.SignalBehavioral})
			input.Enrichment = enrichment.Result{Available: tc.available, Found: tc.found, ASN: tc.asn, NetworkType: "hosting"}
			incident := engine.Evaluate(input)
			if tc.excluded {
				if incident.Score != 0 || incident.Decision != model.DecisionNormal || len(incident.Signals) != 0 {
					t.Fatalf("Google scored: %+v", incident)
				}
			} else if incident.Decision != model.DecisionWouldBlock {
				t.Fatalf("unknown/nonexcluded client was exempted: %+v", incident)
			}
		})
	}
}

func asnNumber(value uint32) *uint32 { return &value }

func TestRotatingExitsExposePerIPDetectionLimit(t *testing.T) {
	for _, status := range []int{200, 404} {
		t.Run(fmt.Sprintf("status %d", status), func(t *testing.T) {
			a := aggregator.New(config.AggregationConfig{MaxActiveRecords: 256, MaxPathsPerIP: 100, Max404PathsPerIP: 100, MaxUserAgentsPerIP: 10, MaxQueriesPerIP: 100, MaxValueBytes: 256})
			at := time.Unix(1_800_000_000, 0)
			for i := 1; i <= 60; i++ {
				a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i)), Method: "POST", Path: "/login", Status: status}, false, at)
			}
			engine, err := New(config.DefaultDetectionConfig())
			if err != nil {
				t.Fatal(err)
			}
			for i := 1; i <= 60; i++ {
				snapshot, ok := a.Snapshot("", netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", i)), 30*time.Second, at)
				if !ok {
					t.Fatal("missing rotating exit")
				}
				signals := detector.HTTP(snapshot)
				signals = append(signals, detector.Impact(snapshot, 60, 1, serverhealth.Snapshot{}, nil)...)
				incident := engine.Evaluate(Input{Snapshot: snapshot, Signals: signals})
				if incident.Score != 0 || incident.Decision != model.DecisionNormal {
					t.Fatalf("a single request acquired unsupported per-IP evidence: %+v", incident)
				}
			}
		})
	}
}

func TestContextOverridesCannotSupplyCorroboration(t *testing.T) {
	at := time.Unix(1_800_000_000, 0)
	cpu, queue := 90.0, int64(2)
	health := serverhealth.Snapshot{Timestamp: at, CPUPercent: &cpu}
	pools := []phpfpm.State{{Name: "www", SampledAt: at, Stats: &phpfpm.Stats{ListenQueue: &queue}}}
	snapshot := aggregator.Snapshot{
		At: at, Window: 30 * time.Second, Requests: 600, PeakRPS: 100, ActiveSeconds: 30,
		StatusFamilies: [6]uint64{5: 600}, ImportantStatuses: map[int]uint64{404: 600},
		QueryPatterns: 1, UniqueQueryValues: 20, QueryPatternSamples: []string{"/items?page={NUMBER}"},
		RequestTimeSamples: 600, RequestTimeNanos: uint64(600 * time.Second),
	}
	signals := detector.HTTP(snapshot)
	signals = append(signals, detector.Impact(snapshot, 600, 1, health, pools)...)
	for _, code := range []string{"HIGH_404_RATE", "QUERY_ENUMERATION", "HIGH_5XX_CONTRIBUTION", "HIGH_TRAFFIC_SHARE", "CPU_SPIKE_CONTRIBUTOR", "PHP_FPM_SATURATION_CONTRIBUTOR", "HIGH_REQUEST_COST"} {
		t.Run(code, func(t *testing.T) {
			rules := config.DefaultDetectionConfig()
			for key := range rules.Weights {
				rules.Weights[key] = 0
			}
			rules.Weights["HIGH_REQUEST_RATE"] = 80
			rules.Weights[code] = 100
			found := false
			for _, signal := range signals {
				if signal.Code == code {
					found = true
				}
			}
			if !found {
				t.Fatal("fixture did not exercise context signal")
			}
			engine, err := New(rules)
			if err != nil {
				t.Fatal(err)
			}
			incident := engine.Evaluate(Input{Snapshot: snapshot, Signals: signals})
			if incident.RawScore != 180 || incident.Score != 100 || incident.Decision != model.DecisionSuspicious {
				t.Fatalf("rate plus context justified WOULD_BLOCK: %+v", incident)
			}
		})
	}
}

func TestZeroWeightedStrongSignalDoesNotCorroborate(t *testing.T) {
	rules := config.DefaultDetectionConfig()
	rules.Weights["PATH_ENUMERATION"] = 0
	rules.Weights["HIGH_REQUEST_RATE"] = 80
	engine, err := New(rules)
	if err != nil {
		t.Fatal(err)
	}
	incident := engine.Evaluate(testInput(
		model.Signal{Code: "PATH_ENUMERATION", Strength: model.SignalStrong},
		model.Signal{Code: "HIGH_REQUEST_RATE", Strength: model.SignalBehavioral},
	))
	if incident.Score != 80 || incident.Decision != model.DecisionSuspicious {
		t.Fatalf("disabled strong signal supplied corroboration: %+v", incident)
	}
}
