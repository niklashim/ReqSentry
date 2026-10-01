package daemon

import (
	"bytes"
	"context"
	"log"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/scoring"
)

func TestRunStopsOnCancellation(t *testing.T) {
	var output bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	daemon := New(config.Config{Server: config.ServerConfig{Name: "test"}, Mode: "monitor"}, log.New(&output, "", 0))
	go func() { done <- daemon.Run(ctx) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("daemon did not stop after cancellation")
	}
	if !strings.Contains(output.String(), "monitor mode") || !strings.Contains(output.String(), "stopped") {
		t.Fatalf("lifecycle logs missing: %s", output.String())
	}
}

func TestAnalysisProducesMonitorOnlyIncident(t *testing.T) {
	var output bytes.Buffer
	cfg := config.Config{
		Server:    config.ServerConfig{Name: "test"},
		Analysis:  config.AnalysisConfig{Window: config.Duration{Duration: 30 * time.Second}},
		Detection: config.DefaultDetectionConfig(),
	}
	daemon := New(cfg, log.New(&output, "", 0))
	geo, err := enrichment.New("../enrichment/testdata")
	if err != nil {
		t.Fatal(err)
	}
	defer geo.Close()
	daemon.SetEnricher(geo)
	rollup := aggregator.New(config.AggregationConfig{
		MaxActiveRecords: 4, MaxPathsPerIP: 64, Max404PathsPerIP: 64,
		MaxUserAgentsPerIP: 8, MaxQueriesPerIP: 16, MaxValueBytes: 256,
	})
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 300; i++ {
		rollup.Observe(model.RequestEvent{
			SiteID: "shop", ClientIP: netip.MustParseAddr("74.209.24.0"),
			Method: "GET", Path: "/users/" + strconv.Itoa(i), Status: 404,
		}, false, now)
	}
	scorer, err := scoring.New(cfg.Detection)
	if err != nil {
		t.Fatal(err)
	}
	daemon.analyzeOnce(rollup, scorer, now)
	incidents := daemon.Incidents()
	if len(incidents) != 2 {
		t.Fatalf("expected site and global incidents, got %d", len(incidents))
	}
	for _, incident := range incidents {
		if incident.Decision != model.DecisionWouldBlock || !incident.MonitorOnly || incident.RulesetVersion != 1 || len(incident.Signals) < 3 {
			t.Fatalf("incident missing explanation or monitor boundary: %+v", incident)
		}
		if incident.EnrichmentStatus != "available" || incident.ASN == nil || *incident.ASN != 14671 || incident.Country != "US" {
			t.Fatalf("local enrichment missing from incident: %+v", incident)
		}
	}
	if !strings.Contains(output.String(), "NO ACTION TAKEN") {
		t.Fatalf("operational log omitted monitor warning: %s", output.String())
	}
}
