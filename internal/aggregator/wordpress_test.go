package aggregator

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

func TestWordPressEndpointClassification(t *testing.T) {
	for _, tc := range []struct {
		path, query string
		want        bool
	}{
		{"/wp-sitemap.xml", "", true}, {"/wp-sitemap-posts-post-1.xml", "", true},
		{"/sitemap_index.xml", "", true}, {"/post-sitemap2.xml", "", true},
		{"/blog/wp-login.php", "", true}, {"/xmlrpc.php", "", true},
		{"/blog/wp-admin/admin-ajax.php", "", true}, {"/wp-json/wp/v2/posts", "", true},
		{"/feed/", "", true}, {"/", "s=private-search", true},
		{"/%77p-sitemap.xml", "", true}, {"/", "%73=private-search", true},
		{"/", "wc-ajax=get_refreshed_fragments", true}, {"/", "rest_route=/wp/v2/posts", true},
		{"/wp-content/uploads/sitemap.png", "", false}, {"/admin-ajax.php", "", false},
		{"/sitemap.xml.jpg", "", false}, {"/api/items", "page=10", false}, {"/", "term=s=foo", false},
	} {
		if got := wordPressEndpoint(tc.path, tc.query); got != tc.want {
			t.Errorf("%s?%s: got %t want %t", tc.path, tc.query, got, tc.want)
		}
	}
}

func TestWordPressCountersAreScopedBoundedAndSurviveDegradation(t *testing.T) {
	a := New(config.AggregationConfig{MaxActiveRecords: 10, MaxValueBytes: 256})
	ip := netip.MustParseAddr("192.0.2.1")
	at := time.Unix(1_800_000_000, 0)
	// Explicitly shed optional rich evidence; the fixed endpoint counters survive.
	a.degraded = true
	for i := 0; i < 30; i++ {
		a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: ip, Method: "GET", Path: "/wp-sitemap.xml", Status: 200}, false, at.Add(time.Duration(i)*time.Second))
		a.Observe(model.RequestEvent{SiteID: "other", ClientIP: ip, Method: "GET", Path: "/assets/app.js", Status: 200}, false, at.Add(time.Duration(i)*time.Second))
	}
	a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: ip, Method: "GET", Path: "/xmlrpc.php", Status: 200}, true, at)
	a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: ip, Method: "GET", Path: "/wp-sitemap.xml", Query: strings.Repeat("s=x&", 100), Status: 200}, false, at)
	a.Observe(model.RequestEvent{SiteID: "shop", ClientIP: ip, Method: "GET", Path: "/", Query: strings.Repeat("s=x&", 100), Status: 200}, false, at)
	end := at.Add(29 * time.Second)
	for _, site := range []string{"shop", ""} {
		got, ok := a.Snapshot(site, ip, 30*time.Second, end)
		if !ok || !got.Saturation.Degraded || got.WordPressRequests != 31 || got.WordPressActiveSeconds != 30 {
			t.Fatalf("scope %q: %+v", site, got)
		}
	}
	other, _ := a.Snapshot("other", ip, 30*time.Second, end)
	if other.WordPressRequests != 0 {
		t.Fatal("static assets were counted as WordPress pressure")
	}
	fresh, _ := a.Snapshot("shop", ip, 30*time.Second, end.Add(30*time.Second))
	if fresh.WordPressRequests != 0 || fresh.WordPressActiveSeconds != 0 {
		t.Fatal("expired endpoint counters remained in the window")
	}
}
