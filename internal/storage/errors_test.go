package storage

import (
	"context"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"io"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestErrorQueueRetentionAndPreview(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	old := now.Add(-48 * time.Hour)
	if err := s.WriteError(model.ErrorEvent{Timestamp: old, SiteID: "shop", Severity: "error", Category: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteError(model.ErrorEvent{Timestamp: now, SiteID: "shop", Severity: "error", Category: "other"}); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteIncident(ctx, model.Incident{Timestamp: old, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Errors: &model.ErrorContext{Observed: 1}}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(ctx, "keep", "value"); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveDashboardMinutes(ctx, []HistorySample{{At: now.Add(-8 * 24 * time.Hour), SiteID: "shop", Requests: 10}}); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	r := config.RetentionConfig{Errors: config.Duration{Duration: 24 * time.Hour}, Minutes: config.Duration{Duration: 7 * 24 * time.Hour}, BatchSize: 1}
	p, err := PreviewPruneFile(ctx, path, r, now)
	if err != nil || p.Errors != 1 || p.Incidents != 0 || p.Minutes != 1 || p.Ranges["error_events"].From == nil || !p.Ranges["error_events"].From.Equal(old) {
		t.Fatalf("preview=%+v %v", p, err)
	}
	events, err := s.RecentErrors(ctx, "shop", "error", "", old.Add(-time.Second), now.Add(time.Second), 50)
	if err != nil || len(events) != 2 {
		t.Fatalf("preview mutated errors %+v %v", events, err)
	}
	if err := s.PruneHistory(ctx, r, now); err != nil {
		t.Fatal(err)
	}
	if after, err := s.PrunePreview(ctx, r, now); err != nil || after.Minutes != 0 || after.Errors != 0 {
		t.Fatalf("bounded background cleanup incomplete: %+v %v", after, err)
	}
	events, err = s.RecentErrors(ctx, "shop", "", "", old.Add(-time.Second), now.Add(time.Second), 50)
	if err != nil || len(events) != 1 {
		t.Fatalf("prune did not respect cutoff %+v %v", events, err)
	}
	incidents, err := s.RecentIncidents(ctx, 10)
	if err != nil || len(incidents) != 1 || incidents[0].Errors.Observed != 1 {
		t.Fatal("immutable incident snapshot lost")
	}
	if v, found, _ := s.GetState(ctx, "keep"); !found || v != "value" {
		t.Fatal("system state pruned")
	}
	status := s.DiskStatus(ctx, ^uint64(0))
	if status.DBBytes == 0 || !status.FreeBytesAvailable || !status.LowDisk || status.LastPrune == nil {
		t.Fatalf("missing disk diagnostics %+v", status)
	}
}
