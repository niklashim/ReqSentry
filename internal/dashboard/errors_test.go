package dashboard

import (
	"context"
	"encoding/json"
	"github.com/niklashim/ReqSentry/internal/model"
	"net/http"
	"testing"
	"time"
)

func TestErrorAPIBoundsAndFilters(t *testing.T) {
	s := apiFixture(t)
	e := model.ErrorEvent{Timestamp: time.Now(), SiteID: "shop", Severity: "error", Category: "timeout", Message: "<script>"}
	if err := s.store.WriteError(e); err != nil {
		t.Fatal(err)
	}
	if err := s.store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := get(t, s, "/api/v1/errors?site=shop&severity=error&category=timeout&limit=1")
	if w.Code != http.StatusOK {
		t.Fatal(w.Code, w.Body.String())
	}
	var body struct {
		Errors []model.ErrorEvent `json:"errors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || len(body.Errors) != 1 {
		t.Fatalf("errors unavailable %s %v", w.Body.String(), err)
	}
	for _, path := range []string{"/api/v1/errors?limit=51", "/api/v1/errors?range=invalid"} {
		if w := get(t, s, path); w.Code != 400 {
			t.Fatal("unbounded query accepted", path)
		}
	}
	if w := get(t, s, "/api/v1/errors?site=other"); w.Code != 200 {
		t.Fatal(w.Code)
	}
}

func TestErrorAssociationKeepsSeparateRequestsAndDeduplicatesSnapshots(t *testing.T) {
	s := apiFixture(t)
	now := time.Now().UTC()
	first := model.ErrorEvent{Timestamp: now, IngestedAt: now, Source: "app.jsonl", SiteID: "shop", Severity: "error", Category: "timeout", Fingerprint: "v1:same", Message: "upstream timeout", RequestID: "one"}
	second := first
	second.RequestID = "two"
	for _, score := range []int{80, 81} {
		incident := model.Incident{Timestamp: now, SiteID: "shop", Score: score, Decision: model.DecisionSuspicious, Errors: &model.ErrorContext{Samples: []model.ErrorMatch{{Event: first, Method: "request_id"}, {Event: second, Method: "request_id"}}}}
		if err := s.store.WriteIncident(context.Background(), incident); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	w := get(t, s, "/api/v1/errors?site=shop&association=request_id&severity=error")
	var body struct {
		Errors   []model.ErrorEvent `json:"errors"`
		Related  []int64            `json:"related_incidents"`
		Timeline []json.RawMessage  `json:"timeline"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || len(body.Errors) != 2 || len(body.Related) != 2 || len(body.Timeline) != 0 {
		t.Fatalf("association response=%s error=%v", w.Body.String(), err)
	}
	if w := get(t, s, "/api/v1/errors?association=made_up"); w.Code != 400 {
		t.Fatal("unknown association accepted", w.Code)
	}
}
