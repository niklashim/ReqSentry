package storage

import (
	"bytes"
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/model"
)

func TestReopenKeepsIncidentsStateAndOffsets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data", "reqsentry.db")
	var diagnostics bytes.Buffer
	store, err := Open(path, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("SQLite file permissions: %v %v", info, err)
	}
	ctx := context.Background()
	for _, address := range []string{"192.0.2.3", "2001:db8::7"} {
		incident := model.Incident{
			Timestamp: time.Unix(100, 0).UTC(), Server: "web", SiteID: "shop",
			ClientIP: netip.MustParseAddr(address), WindowStart: time.Unix(70, 0).UTC(),
			WindowEnd: time.Unix(100, 0).UTC(), Requests: 42, PeakRPS: 5,
			Score: 80, Decision: model.DecisionWouldBlock, RulesetVersion: 2, MonitorOnly: true,
			Signals: []model.Signal{{Code: "HIGH_404_DIVERSITY", Weight: 25, Evidence: map[string]any{"paths": 40}}},
		}
		if err := store.WriteIncident(ctx, incident); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetState(ctx, "maxmind.last_success", "2026-10-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	checkpoint := Offset{Device: 1<<62 + 4, Inode: 123, Bytes: 4096}
	if err := store.SaveOffset(ctx, "/var/log/nginx/shop.log", checkpoint); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	incidents, err := store.RecentIncidents(ctx, 10)
	if err != nil || len(incidents) != 2 {
		t.Fatalf("incidents after reopen: %d %v", len(incidents), err)
	}
	if incidents[0].ClientIP.String() != "2001:db8::7" || incidents[1].ClientIP.String() != "192.0.2.3" ||
		incidents[0].Signals[0].Evidence["paths"] != float64(40) || incidents[0].RulesetVersion != 2 {
		t.Fatalf("incident evidence lost: %+v", incidents)
	}
	value, found, err := store.GetState(ctx, "maxmind.last_success")
	if err != nil || !found || value != "2026-10-01T00:00:00Z" {
		t.Fatalf("state after reopen: %q %t %v", value, found, err)
	}
	got, found, err := store.LoadOffset(ctx, "/var/log/nginx/shop.log")
	if err != nil || !found || got != checkpoint {
		t.Fatalf("checkpoint after reopen: %+v %t %v", got, found, err)
	}
	var windows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM traffic_windows`).Scan(&windows); err != nil || windows != 2 {
		t.Fatalf("traffic windows: %d %v", windows, err)
	}
	if diagnostics.Len() != 0 {
		t.Fatalf("unexpected SQLite error: %s", diagnostics.String())
	}
}

func TestFlushReportsFailedBatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "reqsentry.db")
	var diagnostics bytes.Buffer
	store, err := Open(path, &diagnostics)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.db.Exec(`DROP TABLE incidents`); err != nil {
		t.Fatal(err)
	}
	if err := store.WriteIncident(context.Background(), model.Incident{ClientIP: netip.MustParseAddr("192.0.2.1")}); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(context.Background()); err == nil {
		t.Fatal("failed incident transaction was hidden from checkpoint barrier")
	}
}
