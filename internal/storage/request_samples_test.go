package storage

import (
	"context"
	"fmt"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"io"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestRequestSampleSearchBoundScopingAndStableID(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "data.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.8")
	for i := 0; i < 12; i++ {
		site, server := "shop", "web-a"
		if i == 10 {
			site = "other"
		}
		if i == 11 {
			server = "web-b"
		}
		incident := model.Incident{Timestamp: now, WindowStart: now.Add(-30 * time.Second), WindowEnd: now, SiteID: site, Server: server, ClientIP: ip, Score: 90, Decision: model.DecisionWouldBlock, EventID: fmt.Sprint(i)}
		for j := 0; j < 8; j++ {
			incident.RequestSamples = append(incident.RequestSamples, model.RequestSample{Timestamp: now.Add(-time.Duration(j) * time.Second), SiteID: site, ClientIP: ip, Method: "GET", Path: fmt.Sprintf("/missing/%d", j), RequestID: fmt.Sprintf("r-%d-%d", i, j), Status: 404})
		}
		if err := s.WriteIncident(ctx, incident); err != nil {
			t.Fatal(err)
		}
		if err := s.WriteIncident(ctx, incident); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	f := RequestSampleFilter{From: now.Add(-time.Hour), To: now.Add(time.Minute), Site: "shop", Server: "web-a", Limit: 50}
	items, total, err := s.SearchRequestSamples(ctx, f)
	if err != nil || total != 50 || len(items) != 50 {
		t.Fatalf("ten incidents should yield fifty samples: %d %d %v", total, len(items), err)
	}
	for _, v := range items {
		if v.Sample.SiteID != "shop" || v.Server != "web-a" {
			t.Fatal("site/server crossed")
		}
	}
	f.Query = "R-0-4"
	items, total, err = s.SearchRequestSamples(ctx, f)
	if err != nil || total != 1 || items[0].Sample.RequestID != "r-0-4" {
		t.Fatalf("request ID search: %+v %d %v", items, total, err)
	}
	f.Query = "r-0-7"
	_, total, err = s.SearchRequestSamples(ctx, f)
	if err != nil || total != 0 {
		t.Fatal("more than five samples persisted")
	}
	f.Query = "/missing/1"
	f.Limit = 3
	items, total, err = s.SearchRequestSamples(ctx, f)
	if err != nil || total != 10 || len(items) != 3 {
		t.Fatalf("pagination: %d %d %v", len(items), total, err)
	}
	f.Status = 500
	_, total, err = s.SearchRequestSamples(ctx, f)
	if err != nil || total != 0 {
		t.Fatal("status filter ignored")
	}
	incidents, total, err := s.SearchIncidents(ctx, IncidentFilter{From: f.From, To: f.To, Site: "shop", Server: "web-a", Query: "r-0-4", MaxScore: 100, Limit: 20})
	if err != nil || total != 1 || len(incidents[0].Incident.RequestSamples) != 5 {
		t.Fatalf("incident text search: %d %v", total, err)
	}
}

func TestFourDayRetentionHidesAndCascadesSamples(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "data.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	now := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	for _, age := range []time.Duration{97 * time.Hour, 95 * time.Hour} {
		at := now.Add(-age)
		site := "shop"
		addr := ip
		if age > 96*time.Hour {
			site = "old-shop"
			addr = netip.MustParseAddr("192.0.2.9")
		}
		incident := model.Incident{Timestamp: at, SiteID: site, Server: "web", ClientIP: addr, RequestSamples: []model.RequestSample{{Timestamp: at, SiteID: site, ClientIP: addr, Method: "GET", Path: "/keep", Status: 200}}}
		if err := s.WriteIncident(ctx, incident); err != nil {
			t.Fatal(err)
		}
		if err := s.WriteError(model.ErrorEvent{Timestamp: at, SiteID: "shop", Severity: "error"}); err != nil {
			t.Fatal(err)
		}
		if err := s.SaveDashboardMinutes(ctx, []HistorySample{{At: at, SiteID: "shop", Requests: 1}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SetState(ctx, "essential", "keep"); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	f := RequestSampleFilter{From: now.Add(-7 * 24 * time.Hour), To: now, Limit: 50}
	_, total, err := s.SearchRequestSamples(ctx, f)
	if err != nil || total != 1 {
		t.Fatalf("expired sample visible before prune: %d %v", total, err)
	}
	if _, found, err := s.IncidentByID(ctx, 1); err != nil || found {
		t.Fatal("expired incident detail visible")
	}
	if v, err := s.RecentIncidents(ctx, 10); err != nil || len(v) != 1 {
		t.Fatal("expired recent incident visible")
	}
	if v, err := s.RecentErrors(ctx, "shop", "", "", f.From, f.To, 50); err != nil || len(v) != 1 {
		t.Fatal("expired error visible")
	}
	r := config.RetentionConfig{}.Effective()
	s.SetRetention(r)
	p, err := s.PrunePreview(ctx, r, now)
	if err != nil || p.Incidents != 1 || p.Errors != 1 || p.Minutes != 1 {
		t.Fatalf("preview %+v %v", p, err)
	}
	if err := s.PruneHistory(ctx, r, now); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"incidents", "incident_requests", "traffic_windows", "error_events", "dashboard_minutes", "ips", "sites"} {
		var count int
		if err := s.readDB.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("%s cascade: %d %v", table, count, err)
		}
	}
	if v, ok, _ := s.GetState(ctx, "essential"); !ok || v != "keep" {
		t.Fatal("essential state pruned")
	}
	r.MaxAge.Duration = 24 * time.Hour
	r.Incidents.Duration = 0
	r.Errors.Duration = 0
	r.Minutes.Duration = 0
	s.SetRetention(r)
	_, total, err = s.SearchRequestSamples(ctx, f)
	if err != nil || total != 0 {
		t.Fatal("shorter config did not hide older history")
	}
	if err := s.PruneHistory(ctx, r, now); err != nil {
		t.Fatal(err)
	}
}
