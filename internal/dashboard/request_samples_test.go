package dashboard

import (
	"context"
	"encoding/json"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/storage"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestRequestSampleAPIAndScopedSearch(t *testing.T) {
	s := apiFixture(t)
	now := time.Now()
	for _, site := range []string{"shop", "other"} {
		item := model.Incident{Timestamp: now, Server: "web", SiteID: site, ClientIP: netip.MustParseAddr("192.0.2.8"), Score: 80, RequestSamples: []model.RequestSample{{Timestamp: now, SiteID: site, ClientIP: netip.MustParseAddr("192.0.2.8"), Path: "/login", Method: "GET", Status: 404, RequestID: "req-id"}}}
		if err := s.store.WriteIncident(context.Background(), item); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := get(t, s, "/api/v1/request-samples?site=shop&server=web&q=REQ-ID&status=404")
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var d struct {
		Samples []storage.StoredRequestSample `json:"samples"`
		Total   int                           `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if d.Total != 1 || d.Samples[0].Sample.SiteID != "shop" {
		t.Fatalf("scope %+v", d)
	}
	for _, q := range []string{"limit=51", "status=99", "ip=invalid", "from=invalid", "incident_id=0", "page=202", "method=" + strings.Repeat("x", 33)} {
		if got := get(t, s, "/api/v1/request-samples?"+q); got.Code != 400 {
			t.Fatalf("invalid %q -> %d", q, got.Code)
		}
	}
	if w := get(t, s, "/api/v1/incidents?q=req-id&site=shop&server=web"); w.Code != 200 {
		t.Fatalf("incident text search %d %s", w.Code, w.Body.String())
	}
}
