package daemon

import (
	"bytes"
	"context"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/scoring"
	"github.com/niklashim/ReqSentry/internal/storage"
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

func TestStartRestartStopWithAccessLog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "site.log")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "smoke"}, Mode: "monitor", AccessFiles: []config.AccessFile{{Path: path, Site: "site"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "state.db")}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(cfg.Database.Path, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for runNumber := 0; runNumber < 2; runNumber++ {
		var logs bytes.Buffer
		service := New(cfg, log.New(&logs, "", 0))
		service.SetCheckpointStore(store)
		service.SetIncidentSink(store)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- service.Run(ctx) }()
		time.Sleep(350 * time.Millisecond)
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		_, err = file.WriteString("192.0.2.1 - - [01/Oct/2026:12:00:00 +0000] \"GET / HTTP/1.1\" 200 12 \"-\" \"Mozilla\"\n")
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		time.Sleep(350 * time.Millisecond)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("daemon did not stop")
		}
		if !strings.Contains(logs.String(), "parsed_requests=1") {
			t.Fatalf("run %d did not ingest exactly one new line: %s", runNumber, logs.String())
		}
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
