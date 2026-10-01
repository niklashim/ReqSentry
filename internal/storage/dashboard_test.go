package storage

import (
	"context"
	"database/sql"
	"io"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/model"
)

func TestDashboardHistoryAndIncidentSearch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	for i := 0; i < 3; i++ {
		sample := HistorySample{At: now.Add(time.Duration(i-2) * time.Minute), SiteID: "shop", Requests: uint64(i + 1), Status404: uint64(i), Complete: true}
		if err := store.SaveDashboardMinutes(ctx, []HistorySample{sample}); err != nil {
			t.Fatal(err)
		}
	}
	items, err := store.DashboardHistory(ctx, "shop", now.Add(-5*time.Minute), now.Add(time.Minute), 100)
	if err != nil || len(items) != 7 || items[0].Missing != true || items[5].Requests != 3 || items[5].Missing {
		t.Fatalf("history=%+v err=%v", items, err)
	}
	incident := model.Incident{Timestamp: now, Server: "web", SiteID: "shop", ClientIP: netip.MustParseAddr("2001:db8::1"), Score: 90, Decision: model.DecisionWouldBlock, Signals: []model.Signal{{Code: "HIGH_404_RATE"}}, MonitorOnly: true}
	if err := store.WriteIncident(ctx, incident); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	counts, bySite, err := store.IncidentMinuteCounts(ctx, now)
	if err != nil || counts.Incidents != 1 || counts.WouldBlock != 1 || bySite["shop"].Incidents != 1 {
		t.Fatalf("minute incident counts=%+v bySite=%+v err=%v", counts, bySite, err)
	}
	filter := IncidentFilter{From: now.Add(-time.Minute), To: now.Add(time.Minute), Site: "shop", IP: "2001:db8::1", Decision: model.DecisionWouldBlock, MinScore: 80, MaxScore: 100, Signal: "HIGH_404_RATE", Limit: 10}
	found, total, err := store.SearchIncidents(ctx, filter)
	if err != nil || total != 1 || len(found) != 1 || found[0].Incident.Score != 90 {
		t.Fatalf("search=%+v total=%d err=%v", found, total, err)
	}
	item, ok, err := store.IncidentByID(ctx, found[0].ID)
	if err != nil || !ok || item.Incident.Signals[0].Code != "HIGH_404_RATE" {
		t.Fatalf("detail=%+v ok=%t err=%v", item, ok, err)
	}
	filter.Signal = "OTHER"
	found, total, err = store.SearchIncidents(ctx, filter)
	if err != nil || total != 0 || len(found) != 0 {
		t.Fatalf("nonmatching search=%+v total=%d err=%v", found, total, err)
	}
}

func TestDashboardHistoryRollsUpCompleteMinutesAndMarksGaps(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "history.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	start := time.Now().UTC().Truncate(time.Minute).Add(-5 * time.Minute)
	for i := 0; i < 6; i++ {
		if i == 3 {
			continue
		}
		incidents := i
		blocks := 0
		item := HistorySample{At: start.Add(time.Duration(i) * time.Minute), SiteID: "site", Requests: 10, Status404: uint64(i), Incidents: &incidents, WouldBlock: &blocks, Complete: true}
		if err := store.SaveDashboardMinutes(context.Background(), []HistorySample{item}); err != nil {
			t.Fatal(err)
		}
	}
	result, err := store.DashboardHistory(context.Background(), "site", start, start.Add(5*time.Minute), 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 3 || result[0].Requests != 20 || result[0].Status404 != 1 || result[0].Incidents == nil || *result[0].Incidents != 1 || result[0].BucketMinutes != 2 || result[0].Missing {
		t.Fatalf("first bucket = %+v", result)
	}
	if result[1].Requests != 10 || !result[1].Missing || result[1].Incidents != nil {
		t.Fatalf("gap bucket = %+v", result[1])
	}
	if result[2].Requests != 20 || result[2].Status404 != 9 || result[2].Missing {
		t.Fatalf("last bucket = %+v", result[2])
	}
}

func TestMigrationBackfillsIncidentSignalIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	incident := model.Incident{Timestamp: now, SiteID: "api", ClientIP: netip.MustParseAddr("192.0.2.1"), Score: 40, Decision: model.DecisionWatch, Signals: []model.Signal{{Code: "QUERY_ENUMERATION"}}}
	if err := store.WriteIncident(context.Background(), incident); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{"DROP TABLE incident_signals", "DROP TABLE dashboard_minutes", "PRAGMA user_version=1"} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	filter := IncidentFilter{From: now.Add(-time.Minute), To: now.Add(time.Minute), MinScore: 0, MaxScore: 100, Signal: "QUERY_ENUMERATION", Limit: 10}
	items, total, err := store.SearchIncidents(context.Background(), filter)
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("backfill=%+v total=%d err=%v", items, total, err)
	}
}

func TestIncidentSearchUsesSubsecondTimeBounds(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "time.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	base := time.Now().UTC().Truncate(time.Second)
	for _, offset := range []time.Duration{100 * time.Millisecond, 900 * time.Millisecond} {
		item := model.Incident{Timestamp: base.Add(offset), SiteID: "site", ClientIP: netip.MustParseAddr("192.0.2.1"), Score: 30, Decision: model.DecisionWatch}
		if err := store.WriteIncident(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	items, total, err := store.SearchIncidents(context.Background(), IncidentFilter{From: base.Add(500 * time.Millisecond), To: base.Add(time.Second), MinScore: 0, MaxScore: 100, Limit: 10})
	if err != nil || total != 1 || len(items) != 1 || !items[0].Incident.Timestamp.Equal(base.Add(900*time.Millisecond)) {
		t.Fatalf("subsecond search items=%+v total=%d err=%v", items, total, err)
	}
}

func TestDashboardReaderDoesNotBlockIncidentWriter(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "state with spaces.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	readTx, err := store.readDB.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer readTx.Rollback()
	var version int
	if err := readTx.QueryRowContext(ctx, "SELECT COUNT(*) FROM incidents").Scan(&version); err != nil {
		t.Fatal(err)
	}
	incident := model.Incident{Timestamp: time.Now().UTC(), SiteID: "site", ClientIP: netip.MustParseAddr("192.0.2.9"), Score: 20, Decision: model.DecisionWatch}
	if err := store.WriteIncident(ctx, incident); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatalf("incident writer stalled behind dashboard reader: %v", err)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	items, total, err := store.SearchIncidents(ctx, IncidentFilter{From: incident.Timestamp.Add(-time.Second), To: incident.Timestamp.Add(time.Second), MinScore: 0, MaxScore: 100, Limit: 10})
	if err != nil || total != 1 || len(items) != 1 {
		t.Fatalf("reader after commit: total=%d items=%v err=%v", total, items, err)
	}
}
