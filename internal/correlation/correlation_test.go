package correlation

import (
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"net/netip"
	"testing"
	"time"
)

func TestAssociationDoesNotAttributeAnOutage(t *testing.T) {
	at := time.Now()
	ip := netip.MustParseAddr("192.0.2.1")
	e := New(config.CorrelationConfig{}, true)
	e.Observe(model.RequestEvent{Timestamp: at, SiteID: "shop", ClientIP: ip, Path: "/api", RequestID: "one"})
	e.ObserveError(model.ErrorEvent{Timestamp: at, SiteID: "shop", RequestID: "one", Category: "upstream_timeout"})
	e.ObserveError(model.ErrorEvent{Timestamp: at, SiteID: "shop", RequestID: "another", Category: "upstream_timeout"})
	e.ObserveError(model.ErrorEvent{Timestamp: at, Category: "resource_limit"})
	e.ObserveError(model.ErrorEvent{Timestamp: at, SiteID: "different", RequestID: "one", Category: "other"})
	c := e.Context(model.Incident{SiteID: "shop", ClientIP: ip, WindowStart: at.Add(-time.Second), WindowEnd: at})
	if c.Observed != 3 || c.Associations["request_id"] != 1 || c.Associations["site_time"] != 1 || c.Associations["server_time"] != 1 || !c.Samples[1].Uncertain {
		t.Fatalf("incorrect attribution: %+v", c)
	}
	e.Observe(model.RequestEvent{Timestamp: at, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.2"), RequestID: "one"})
	c = e.Context(model.Incident{SiteID: "shop", ClientIP: ip, WindowStart: at.Add(-time.Second), WindowEnd: at})
	if c.Associations["request_id"] != 0 {
		t.Fatal("reused log identifier treated as unique")
	}
}
func TestEvidenceCapsAndExpiry(t *testing.T) {
	at := time.Now()
	e := New(config.CorrelationConfig{MaxEvents: 32}, true)
	for j := 0; j < 100; j++ {
		e.ObserveError(model.ErrorEvent{Timestamp: at, SiteID: "shop", Category: "other"})
	}
	c := e.Context(model.Incident{SiteID: "shop", WindowStart: at.Add(-time.Second), WindowEnd: at})
	if c.Observed != 32 || len(c.Samples) != 8 || c.Dropped != 68 {
		t.Fatalf("unbounded evidence: %+v", c)
	}
	e.Prune(at.Add(10 * time.Minute))
	if len(e.Recent("", at, at.Add(time.Second), 50)) != 0 {
		t.Fatal("expired errors retained")
	}
}

func BenchmarkFullErrorRing(b *testing.B) {
	e := New(config.CorrelationConfig{MaxEvents: 4096}, true)
	event := model.ErrorEvent{Timestamp: time.Now(), Message: "bounded"}
	for j := 0; j < 4096; j++ {
		e.ObserveError(event)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for j := 0; j < b.N; j++ {
		e.ObserveError(event)
	}
}
