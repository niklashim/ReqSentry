package aggregator

import (
	"fmt"
	"github.com/niklashim/ReqSentry/internal/model"
	"net/netip"
	"testing"
	"time"
)

func TestSamplesStayBoundedScopedAndProtectClosedWindow(t *testing.T) {
	a := New(limits(), 30*time.Second)
	start := time.Now().Truncate(time.Minute)
	ip := netip.MustParseAddr("192.0.2.8")
	bytes := int64(12)
	for i := 0; i < 100; i++ {
		at := start.Add(time.Duration(i) * time.Millisecond)
		a.Observe(model.RequestEvent{Timestamp: at, SiteID: "shop", ClientIP: ip, Method: "GET", Path: fmt.Sprintf("/sample/%d?token=secret", i), Status: 404, Bytes: &bytes, RequestID: fmt.Sprint(i)}, false, at)
	}
	other := start.Add(30 * time.Second)
	a.Observe(model.RequestEvent{Timestamp: other, SiteID: "shop", ClientIP: ip, Method: "GET", Path: "/next", Status: 200}, false, other)
	a.Observe(model.RequestEvent{Timestamp: other, SiteID: "other", ClientIP: ip, Method: "GET", Path: "/other", Status: 200}, false, other)
	a.Observe(model.RequestEvent{Timestamp: other, SiteID: "shop", ClientIP: ip, Method: "GET", Path: "/allowlisted", Status: 200}, true, other)
	bytes = 999
	s, ok := a.Snapshot("shop", ip, 30*time.Second, other.Add(-time.Nanosecond))
	if !ok || len(s.RequestSamples) != 5 || s.RequestSamples[0].RequestID != "95" || s.RequestSamples[4].RequestID != "99" {
		t.Fatalf("closed window samples: %+v", s.RequestSamples)
	}
	for _, v := range s.RequestSamples {
		if v.SiteID != "shop" || v.Bytes == nil || *v.Bytes != 12 || v.Path != fmt.Sprintf("/sample/%s", v.RequestID) {
			t.Fatalf("scoping/copy/privacy: %+v", v)
		}
	}
	*s.RequestSamples[0].Bytes = 0
	s.RequestSamples[0].Path = "mutated"
	s, _ = a.Snapshot("shop", ip, 30*time.Second, other.Add(-time.Nanosecond))
	if *s.RequestSamples[0].Bytes != 12 || s.RequestSamples[0].Path == "mutated" {
		t.Fatal("snapshot mutated retained evidence")
	}
	s, _ = a.Snapshot("shop", ip, 30*time.Second, other.Add(time.Second))
	if len(s.RequestSamples) != 1 || s.RequestSamples[0].Path != "/next" {
		t.Fatalf("expired/allowlisted samples: %+v", s.RequestSamples)
	}
}

func TestSampleLateArrivalAndEpochExpiry(t *testing.T) {
	a := New(limits(), 30*time.Second)
	now := time.Now().Truncate(time.Minute)
	ip := netip.MustParseAddr("192.0.2.1")
	for _, sec := range []int{10, 9, 8, 7, 6, 5, 4, 3, 2, 1} {
		at := now.Add(time.Duration(sec) * time.Second)
		a.Observe(model.RequestEvent{SiteID: "s", ClientIP: ip, Status: 200, Method: "GET", Path: fmt.Sprint(sec)}, false, at)
	}
	s, _ := a.Snapshot("s", ip, 30*time.Second, now.Add(10*time.Second))
	if len(s.RequestSamples) != 5 || s.RequestSamples[0].Path != "6" {
		t.Fatalf("late arrivals evicted newer samples: %+v", s.RequestSamples)
	}
	a.Prune(now.Add(80 * time.Second))
	if _, ok := a.Snapshot("s", ip, 30*time.Second, now.Add(80*time.Second)); ok {
		t.Fatal("expired record retained")
	}
}

func BenchmarkObserveIncidentSamples(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprintf("sampling=%t", enabled), func(b *testing.B) {
			a := New(limits(), 30*time.Second)
			if !enabled {
				a.sampleSeconds = 0
			}
			now := time.Now()
			size := int64(123)
			duration := 23 * time.Millisecond
			event := model.RequestEvent{Timestamp: now, SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.8"), Method: "GET", Path: "/missing/item", Status: 404, RequestID: "request-123", Bytes: &size, RequestTime: &duration}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a.Observe(event, false, now)
			}
		})
	}
}
