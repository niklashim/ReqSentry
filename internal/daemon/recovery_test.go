package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/scoring"
	"github.com/niklashim/ReqSentry/internal/storage"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestRecoveryPreservesCrossCheckpointScanAndDeduplicates(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "requests.jsonl")
	var lines bytes.Buffer
	at := time.Now().Truncate(30 * time.Second).Add(-5 * time.Second)
	for j := 0; j < 300; j++ {
		b, _ := json.Marshal(map[string]any{"timestamp": at, "client_ip": "192.0.2.1", "method": "GET", "path": fmt.Sprintf("/scan/%d", j), "status": 404})
		lines.Write(b)
		lines.WriteByte('\n')
	}
	complete := lines.Len()
	lines.WriteString(`{"timestamp":`)
	if err := os.WriteFile(path, lines.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "test"}, AccessFiles: []config.AccessFile{{Path: path, Site: "shop", Format: "json"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "state.db")}, Recovery: config.RecoveryConfig{Enabled: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	store, err := storage.Open(cfg.Database.Path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	st, _ := os.Stat(path)
	identity := st.Sys().(*syscall.Stat_t)
	if err := store.SaveOffset(context.Background(), path, storage.Offset{Device: uint64(identity.Dev), Inode: identity.Ino, Bytes: 0}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		d := New(cfg, log.New(io.Discard, "", 0))
		d.SetCheckpointStore(store)
		d.SetIncidentSink(store)
		resume, status, err := d.recover(context.Background(), aggregator.New(cfg.Aggregation))
		if err != nil || status.Replayed != 300 || resume[path].Bytes != int64(complete) {
			t.Fatalf("recovery=%+v resume=%+v err=%v", status, resume, err)
		}
		items, err := store.RecentIncidents(context.Background(), 10)
		if err != nil || len(items) != 2 {
			t.Fatalf("duplicate/lost incidents: %d %v", len(items), err)
		}
		for _, i := range items {
			if i.Requests != 300 || i.EventID == "" || !i.MonitorOnly {
				t.Fatalf("lost window evidence %+v", i)
			}
		}
	}
	cfg.Recovery.MaxBytes = 1
	d := New(cfg, log.New(io.Discard, "", 0))
	d.SetCheckpointStore(store)
	if _, _, err := d.recover(context.Background(), aggregator.New(cfg.Aggregation)); err == nil {
		t.Fatal("unbounded recovery accepted")
	}
	offset, _, _ := store.LoadOffset(context.Background(), path)
	if offset.Bytes != 0 {
		t.Fatal("unsafe recovery advanced prior checkpoint")
	}
}

func TestRecoveryValidatesOrderingBeforeAnyIncidentEmission(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "access.jsonl")
	at := time.Now().UTC().Truncate(30 * time.Second).Add(-35 * time.Second)
	var lines strings.Builder
	for j := 0; j < 300; j++ {
		fmt.Fprintf(&lines, "{\"timestamp\":%q,\"client_ip\":\"192.0.2.1\",\"method\":\"GET\",\"path\":\"/scan/%d\",\"status\":404}\n", at.Format(time.RFC3339Nano), j)
	}
	for _, timestamp := range []time.Time{at.Add(30 * time.Second), at.Add(-time.Second)} {
		fmt.Fprintf(&lines, "{\"timestamp\":%q,\"client_ip\":\"192.0.2.1\",\"method\":\"GET\",\"path\":\"/\",\"status\":200}\n", timestamp.Format(time.RFC3339Nano))
	}
	if err := os.WriteFile(path, []byte(lines.String()), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Server: config.ServerConfig{Name: "test"}, AccessFiles: []config.AccessFile{{Path: path, Site: "shop", Format: "json"}}, Database: config.DatabaseConfig{Path: filepath.Join(dir, "state.db")}, Recovery: config.RecoveryConfig{Enabled: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := storage.Open(cfg.Database.Path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	info, _ := os.Stat(path)
	identity := info.Sys().(*syscall.Stat_t)
	if err := s.SaveOffset(context.Background(), path, storage.Offset{Device: uint64(identity.Dev), Inode: identity.Ino}); err != nil {
		t.Fatal(err)
	}
	d := New(cfg, log.New(io.Discard, "", 0))
	d.SetCheckpointStore(s)
	d.SetIncidentSink(s)
	rollup := aggregator.New(cfg.Aggregation)
	if _, _, err := d.recover(context.Background(), rollup); err == nil {
		t.Fatal("out-of-order recovery accepted")
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, err := s.RecentIncidents(context.Background(), 10)
	if err != nil || len(items) != 0 || rollup.TotalRequests(time.Minute, time.Now()) != 0 {
		t.Fatalf("failed recovery partially emitted or warmed: incidents=%d err=%v", len(items), err)
	}
}

func TestErrorStormLeavesRequestCountsAndScoresUnchanged(t *testing.T) {
	cfg := config.Config{Server: config.ServerConfig{Name: "test"}, AccessFiles: []config.AccessFile{{Path: "/tmp/access.log", Site: "shop"}}, ErrorFiles: []config.AccessFile{{Path: "/tmp/error.log", Site: "shop", Type: "nginx"}}, Database: config.DatabaseConfig{Path: "/tmp/unused-state.db"}}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	d := New(cfg, log.New(io.Discard, "", 0))
	rollup := aggregator.New(cfg.Aggregation)
	at := time.Now()
	for j := 0; j < 10000; j++ {
		d.errors.ObserveError(model.ErrorEvent{Timestamp: at, SiteID: "shop", Severity: "critical", Category: "upstream_timeout"})
	}
	for j := 0; j < 10; j++ {
		rollup.Observe(model.RequestEvent{Timestamp: at, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET", Path: "/", Status: 200}, false, at)
	}
	engine, err := scoring.New(cfg.Detection)
	if err != nil {
		t.Fatal(err)
	}
	d.analyzeOnce(rollup, engine, at)
	if len(d.Incidents()) != 0 || rollup.TotalRequests(time.Minute, at) != 10 {
		t.Fatal("error storm changed traffic or scores")
	}
}

func TestDelayedClosedAnalysisMatchesBoundaryScores(t *testing.T) {
	for _, seconds := range []int{1, 30, 31, 60} {
		window := time.Duration(seconds) * time.Second
		cfg := config.Config{Server: config.ServerConfig{Name: "phase-test"}, Database: config.DatabaseConfig{Path: "/tmp/phase-state.db"}, AccessFiles: []config.AccessFile{{Path: "/tmp/phase.log", Site: "shop"}}, Analysis: config.AnalysisConfig{Window: config.Duration{Duration: window}}}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		boundary := time.Now().Truncate(window)
		evaluate := func(phase int) []model.Incident {
			d := New(cfg, log.New(io.Discard, "", 0))
			d.recoveryActive = true
			a := aggregator.New(cfg.Aggregation, window)
			a.RetainClosedWindows()
			for i := range 300 {
				at := boundary.Add(-time.Second)
				a.Observe(model.RequestEvent{Timestamp: at, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET", Path: fmt.Sprintf("/scan/%d", i), Status: 404}, false, at)
			}
			for i := 0; i <= phase; i++ {
				at := boundary.Add(time.Duration(i) * time.Second)
				a.Observe(model.RequestEvent{Timestamp: at, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Method: "GET", Path: "/", Status: 200}, false, at)
			}
			scorer, err := scoring.New(cfg.Detection)
			if err != nil {
				t.Fatal(err)
			}
			// Model the same closed target window evaluated after newer buckets arrived.
			d.analyzeOnce(a, scorer, boundary.Add(time.Millisecond))
			return d.Incidents()
		}
		original := evaluate(0)
		if len(original) != 2 {
			t.Fatalf("window=%d baseline=%d", seconds, len(original))
		}
		for _, phase := range []int{1, 15, 45, 59} {
			delayed := evaluate(phase)
			if len(delayed) != len(original) {
				t.Fatalf("window=%d phase=%d lost incidents", seconds, phase)
			}
			for i, item := range delayed {
				if item.Score != original[i].Score || item.EventID != original[i].EventID || item.Requests != original[i].Requests || len(item.RequestSamples) != 5 {
					t.Fatalf("window=%d phase=%d altered evidence: %+v", seconds, phase, item)
				}
			}
		}
	}
}
