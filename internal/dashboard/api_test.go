package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/phpfpm"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
	"github.com/niklashim/ReqSentry/internal/storage"
)

type fixtureSource struct {
	view      aggregator.DashboardView
	incidents []model.Incident
}

type countingDashboardSource struct {
	fixtureSource
	calls int
}

func (s *countingDashboardSource) Dashboard(_ time.Duration, _ int) aggregator.DashboardView {
	s.calls++
	return s.view
}

func (f fixtureSource) ServerName() string                                        { return "test-host" }
func (f fixtureSource) Dashboard(_ time.Duration, _ int) aggregator.DashboardView { return f.view }
func (f fixtureSource) IPSnapshot(_ string, ip netip.Addr, _ time.Duration) (aggregator.Snapshot, bool) {
	return aggregator.Snapshot{ClientIP: ip, Requests: 8, ImportantStatuses: map[int]uint64{404: 2}}, ip.String() == "192.0.2.8"
}
func (f fixtureSource) Enrich(netip.Addr) (enrichment.Result, error) {
	asn := uint32(64500)
	return enrichment.Result{Available: true, Found: true, ASN: &asn, ASNOrganization: "Example"}, nil
}
func (f fixtureSource) Health() (serverhealth.Snapshot, bool) { return serverhealth.Snapshot{}, false }
func (f fixtureSource) PHPFPM() []phpfpm.State                { return nil }
func (f fixtureSource) Incidents() []model.Incident           { return f.incidents }
func (f fixtureSource) DeepAnalysisActive() bool              { return true }

func apiFixture(t *testing.T) *Server {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	item := model.Incident{Timestamp: now, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.8"), Score: 82, Decision: model.DecisionWouldBlock, Signals: []model.Signal{{Code: "HIGH_404_RATE"}}}
	if err := store.WriteIncident(context.Background(), item); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	view := aggregator.DashboardView{At: now, WindowSeconds: 60, Requests: 10, Statuses: map[int]uint64{404: 2}, Methods: map[string]uint64{"GET": 10}, Sites: []aggregator.DashboardSite{{SiteID: "shop", Requests: 10}, {SiteID: "shop/api"}}, TopIPs: []aggregator.DashboardIP{{IP: netip.MustParseAddr("192.0.2.8"), Requests: 8, UserAgentRequests: map[string]uint64{"fixture-agent": 8}}}, SiteIPs: map[string][]aggregator.DashboardIP{"shop": {{IP: netip.MustParseAddr("192.0.2.8"), Requests: 8}}}}
	cfg := config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 8090, AllowedIPs: []string{"127.0.0.1"}}
	s, err := New(cfg, fixtureSource{view: view, incidents: []model.Incident{item}}, store, nil)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "http://localhost"+path, nil)
	r.RemoteAddr = "127.0.0.1:12345"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestAPIAndAssets(t *testing.T) {
	s := apiFixture(t)
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/v1/status", "/api/v1/server", "/api/v1/stats", "/api/v1/sites", "/api/v1/sites/shop", "/api/v1/sites/shop%2Fapi", "/api/v1/ips", "/api/v1/ips/192.0.2.8", "/api/v1/asns", "/api/v1/asns/64500", "/api/v1/phpfpm", "/api/v1/user-agents", "/api/v1/incidents?signal=HIGH_404_RATE"} {
		w := get(t, s, path)
		if w.Code != 200 {
			t.Errorf("%s status=%d body=%s", path, w.Code, w.Body.String())
			continue
		}
		if strings.HasPrefix(path, "/api/") {
			var data any
			if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
				t.Errorf("%s invalid JSON: %v", path, err)
			}
		}
	}
	if w := get(t, s, "/api/v1/sites/missing"); w.Code != 404 {
		t.Errorf("unknown site=%d", w.Code)
	}
	if w := get(t, s, "/api/v1/ips/garbage"); w.Code != 400 {
		t.Errorf("invalid IP=%d", w.Code)
	}
	if w := get(t, s, "/api/v1/ips/192.0.2.9"); w.Code != 404 {
		t.Errorf("unknown IP=%d", w.Code)
	}
	if w := get(t, s, "/api/v1/stats?range=all"); w.Code != 400 {
		t.Errorf("invalid range=%d", w.Code)
	}
	if w := get(t, s, "/api/v1/incidents?limit=1000"); w.Code != 400 {
		t.Errorf("oversized limit=%d", w.Code)
	}
	if w := get(t, s, "/api/v1/incidents?decision=BLOCK"); w.Code != 400 {
		t.Errorf("invalid decision=%d", w.Code)
	}
	if w := get(t, s, "/app.js"); !strings.Contains(w.Body.String(), "EventSource") {
		t.Fatal("embedded app missing")
	}
	if w := get(t, s, "/api/v1/user-agents"); !strings.Contains(w.Body.String(), `"recent_would_block_ips":1`) {
		t.Fatalf("User-Agent incident association missing: %s", w.Body.String())
	}
}

func TestRoutesWithoutLiveStatsSkipDashboardScan(t *testing.T) {
	s := apiFixture(t)
	source := &countingDashboardSource{}
	s.source = source
	for _, path := range []string{"/api/v1/server", "/api/v1/phpfpm", "/api/v1/incidents?limit=1", "/api/v1/status"} {
		if w := get(t, s, path); w.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, w.Code)
		}
	}
	if source.calls != 0 {
		t.Fatalf("unneeded dashboard scans=%d", source.calls)
	}
	if w := get(t, s, "/api/v1/stats?range=1m"); w.Code != http.StatusOK || source.calls != 1 {
		t.Fatalf("live stats status=%d scans=%d", w.Code, source.calls)
	}
}

func TestHubKeepsLatestForSlowClient(t *testing.T) {
	h := newEventHub()
	client := make(chan []byte, 1)
	other := make(chan []byte, 1)
	h.clients[client] = struct{}{}
	h.clients[other] = struct{}{}
	h.publish([]byte("first"))
	h.publish([]byte("second"))
	if got := string(<-client); got != "second" {
		t.Fatalf("queued %q", got)
	}
	if string(h.last) != "second" {
		t.Fatalf("last=%q", h.last)
	}
	if got := string(<-other); got != "second" {
		t.Fatalf("other client queued %q", got)
	}
}

func TestDuplicateForwardedHeadersAreRejected(t *testing.T) {
	s := newTestServer(t, config.WebConfig{AllowedIPs: []string{"203.0.113.5"}, TrustedProxies: []string{"127.0.0.1"}}, io.Discard)
	r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/status", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Add("X-Forwarded-For", "203.0.113.5")
	r.Header.Add("X-Forwarded-For", "198.51.100.6")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatalf("duplicate XFF status=%d", w.Code)
	}
}

func TestStreamClientLimitAndDisconnect(t *testing.T) {
	s := apiFixture(t)
	s.config.Realtime.MaxClients = 1
	ctx, cancel := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/stream", nil).WithContext(ctx)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { s.Handler().ServeHTTP(w, r); close(done) }()
	deadline := time.After(time.Second)
	for s.clients.Load() != 1 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("stream did not register")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if got := get(t, s, "/api/v1/stream").Code; got != 503 {
		cancel()
		t.Fatalf("second client=%d", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stream did not disconnect")
	}
	if got := s.clients.Load(); got != 0 {
		t.Fatalf("clients after disconnect=%d", got)
	}
}

func TestStreamInitialSnapshot(t *testing.T) {
	s := apiFixture(t)
	s.publish()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/stream", nil).WithContext(ctx)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "event: snapshot\ndata: ") {
		t.Fatalf("initial event status=%d body=%s", w.Code, w.Body.String())
	}
}
