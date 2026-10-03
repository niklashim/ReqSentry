package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/niklashim/ReqSentry/internal/config"
)

func FuzzDashboardReadRoutes(f *testing.F) {
	for _, path := range []string{
		"/api/v1/stats?range=1m",
		"/api/v1/ips/2001%3Adb8%3A%3A1",
		"/api/v1/incidents?limit=999999",
		"/api/v1/sites/%2e%2e",
		"/api/v1/stream",
		"/../../private",
		"/style.css",
	} {
		f.Add(path)
	}
	s, err := New(config.WebConfig{Enabled: true, Listen: "127.0.0.1", Port: 8090, AllowedIPs: []string{"127.0.0.1"}}, fixtureSource{}, nil, nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, path string) {
		if !strings.HasPrefix(path, "/") || len(path) > 4096 {
			return
		}
		r, err := http.NewRequest(http.MethodGet, "http://localhost"+path, nil)
		if err != nil {
			return
		}
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // A stream route must return instead of waiting for events.
		r = r.WithContext(ctx)
		r.RemoteAddr = "127.0.0.1:1234"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code < 200 || w.Code >= 600 || w.Body.Len() > maxJSONResponseBytes {
			t.Fatalf("path=%q status=%d response_bytes=%d", path, w.Code, w.Body.Len())
		}
	})
}
