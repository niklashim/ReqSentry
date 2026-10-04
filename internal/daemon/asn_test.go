package daemon

import (
	"fmt"
	"io"
	"log"
	"net/netip"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/scoring"
)

func TestASNExclusionsSkipIncidentsWithoutChangingTrafficTotals(t *testing.T) {
	rules := config.DefaultDetectionConfig()
	// This licensed test fixture contains AS14671; the default AS15169 policy
	// is independently exercised with resolved metadata in the scoring tests.
	rules.ExcludedASNs = []uint32{14671}
	cfg := config.Config{Server: config.ServerConfig{Name: "fixture"}, Detection: rules, Analysis: config.AnalysisConfig{Window: config.Duration{Duration: 30 * time.Second}}}
	d := New(cfg, log.New(io.Discard, "", 0))
	geo, err := enrichment.New("../enrichment/testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer geo.Close()
	d.SetEnricher(geo)
	a := aggregator.New(config.AggregationConfig{MaxActiveRecords: 10, MaxPathsPerIP: 64, Max404PathsPerIP: 64, MaxUserAgentsPerIP: 8, MaxQueriesPerIP: 16, MaxValueBytes: 256})
	at := time.Unix(1_800_000_000, 0)
	for _, ip := range []string{"74.209.24.0", "192.0.2.1"} {
		for i := 0; i < 300; i++ {
			a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: netip.MustParseAddr(ip), Method: "GET", Path: fmt.Sprintf("/users/%d", i), Status: 404}, false, at)
		}
	}
	engine, err := scoring.New(rules)
	if err != nil {
		t.Fatal(err)
	}
	d.analyzeOnce(a, engine, at)
	if a.TotalRequests(30*time.Second, at) != 600 || d.asnExcludedWindows.Load() != 2 || d.asnUnknownWindows.Load() != 2 || len(d.Incidents()) != 2 {
		t.Fatalf("traffic/exclusion mismatch: total=%d excluded=%d unknown=%d incidents=%d", a.TotalRequests(30*time.Second, at), d.asnExcludedWindows.Load(), d.asnUnknownWindows.Load(), len(d.Incidents()))
	}
	for _, incident := range d.Incidents() {
		if incident.ClientIP.String() != "192.0.2.1" {
			t.Fatal("excluded ASN emitted an incident")
		}
	}
}
