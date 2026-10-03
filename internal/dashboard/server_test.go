package dashboard

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
)

type blockingDashboardSource struct {
	fixtureSource
	entered chan struct{}
	release chan struct{}
}

func (s blockingDashboardSource) Dashboard(time.Duration, int) aggregator.DashboardView {
	s.entered <- struct{}{}
	<-s.release
	return aggregator.DashboardView{}
}

func newTestServer(t *testing.T, cfg config.WebConfig, diagnostics io.Writer) *Server {
	t.Helper()
	cfg.Enabled = true
	cfg.Listen = "127.0.0.1"
	cfg.Port = 8090
	s, err := New(cfg, nil, nil, log.New(diagnostics, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func request(s *Server, ip, xff, method string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://localhost/api/v1/status?secret=never-log", nil)
	r.RemoteAddr = ip
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestAccessPolicyAndProxySpoofing(t *testing.T) {
	for _, test := range []struct {
		name             string
		allowed, trusted []string
		peer, xff        string
		want             int
	}{
		{"empty deny", nil, nil, "127.0.0.1:1234", "", 403},
		{"localhost", []string{"127.0.0.1"}, nil, "127.0.0.1:1234", "", 200},
		{"IPv4 direct", []string{"203.0.113.42"}, nil, "203.0.113.42:1234", "", 200},
		{"IPv4 denied", []string{"203.0.113.42"}, nil, "203.0.113.43:1234", "", 403},
		{"IPv4 CIDR", []string{"203.0.113.0/24"}, nil, "203.0.113.42:1234", "", 200},
		{"IPv6 direct", []string{"2001:db8::7"}, nil, "[2001:db8::7]:1234", "", 200},
		{"IPv6 denied", []string{"2001:db8::7"}, nil, "[2001:db8::8]:1234", "", 403},
		{"IPv6 CIDR", []string{"2001:db8::/48"}, nil, "[2001:db8::7]:1234", "", 200},
		{"trusted proxy", []string{"203.0.113.42"}, []string{"127.0.0.1"}, "127.0.0.1:1234", "203.0.113.42", 200},
		{"trusted IPv6 forwarded", []string{"2001:db8::7"}, []string{"127.0.0.1"}, "127.0.0.1:1234", "2001:db8::7", 200},
		{"untrusted spoof", []string{"203.0.113.42"}, []string{"127.0.0.1"}, "198.51.100.3:1234", "203.0.113.42", 403},
		{"spoofed leftmost", []string{"203.0.113.42"}, []string{"127.0.0.1"}, "127.0.0.1:1234", "203.0.113.42, 198.51.100.3", 403},
		{"trusted chain", []string{"203.0.113.42"}, []string{"127.0.0.1", "10.0.0.0/8"}, "127.0.0.1:1234", "203.0.113.42, 10.0.0.5", 200},
		{"missing forwarded", []string{"127.0.0.1"}, []string{"127.0.0.1"}, "127.0.0.1:1234", "", 403},
		{"malformed forwarded", []string{"127.0.0.1"}, []string{"127.0.0.1"}, "127.0.0.1:1234", "garbage", 403},
	} {
		t.Run(test.name, func(t *testing.T) {
			s := newTestServer(t, config.WebConfig{AllowedIPs: test.allowed, TrustedProxies: test.trusted}, io.Discard)
			w := request(s, test.peer, test.xff, http.MethodGet)
			if w.Code != test.want {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if test.want == 403 && strings.Contains(w.Body.String(), "status") {
				t.Fatal("denial leaked API data")
			}
		})
	}
}

func TestAuthenticationAndReadOnlyRoutes(t *testing.T) {
	t.Setenv("REQSENTRY_TEST_WEB_PASSWORD", "top-secret")
	var logs bytes.Buffer
	s := newTestServer(t, config.WebConfig{AllowedIPs: []string{"127.0.0.1"}, Auth: config.WebAuthConfig{Enabled: true, Username: "admin", PasswordEnv: "REQSENTRY_TEST_WEB_PASSWORD"}}, &logs)
	r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/status?secret=never-log", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("missing auth status=%d", w.Code)
	}
	r.SetBasicAuth("admin", "wrong")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("bad auth status=%d", w.Code)
	}
	r.SetBasicAuth("admin", "top-secret")
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "monitor") {
		t.Fatalf("good auth status=%d body=%s", w.Code, w.Body.String())
	}
	r.Method = http.MethodPost
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatalf("mutation status=%d", w.Code)
	}
	if strings.Contains(logs.String(), "top-secret") || strings.Contains(logs.String(), "never-log") {
		t.Fatalf("secret logged: %s", logs.String())
	}
}

func TestDashboardRequestLimitAndRecovery(t *testing.T) {
	s := newTestServer(t, config.WebConfig{AllowedIPs: []string{"127.0.0.1"}}, io.Discard)
	s.requests = make(chan struct{}, 1)
	blocked := blockingDashboardSource{entered: make(chan struct{}, 1), release: make(chan struct{})}
	s.source = blocked
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- get(t, s, "/api/v1/stats")
	}()
	select {
	case <-blocked.entered:
	case <-time.After(time.Second):
		close(blocked.release)
		t.Fatal("first request did not enter the dashboard source")
	}
	if w := get(t, s, "/api/v1/status"); w.Code != http.StatusServiceUnavailable {
		close(blocked.release)
		t.Fatalf("overloaded request status=%d", w.Code)
	}
	if state := s.State(); state.ActiveRequests != 1 || state.RejectedRequests != 1 {
		close(blocked.release)
		t.Fatalf("overload counters=%+v", state)
	}
	close(blocked.release)
	select {
	case w := <-done:
		if w.Code != http.StatusOK {
			t.Fatalf("first request status=%d", w.Code)
		}
	case <-time.After(time.Second):
		t.Fatal("first request did not finish")
	}
	if w := get(t, s, "/api/v1/status"); w.Code != http.StatusOK {
		t.Fatalf("request after recovery status=%d", w.Code)
	}
}

func TestDashboardRouteSecurityAndResponseSize(t *testing.T) {
	s := newTestServer(t, config.WebConfig{AllowedIPs: []string{"127.0.0.1"}}, io.Discard)
	for _, path := range []string{"/", "/app.js", "/style.css", "/api/v1/status", "/api/v1/stats", "/api/v1/stream"} {
		r := httptest.NewRequest(http.MethodGet, "http://localhost"+path, nil)
		r.RemoteAddr = "192.0.2.1:1234"
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("denied route %s status=%d headers=%v", path, w.Code, w.Header())
		}
		r.RemoteAddr = "127.0.0.1:1234"
		r.Method = http.MethodPost
		w = httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("mutation route %s status=%d", path, w.Code)
		}
	}
	if w := get(t, s, "/private"); w.Code != http.StatusNotFound {
		t.Fatalf("unknown asset status=%d", w.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "http://localhost/api/v1/status", strings.NewReader("unexpected body"))
	r.RemoteAddr = "127.0.0.1:1234"
	bodyResponse := httptest.NewRecorder()
	s.Handler().ServeHTTP(bodyResponse, r)
	if bodyResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("GET body status=%d", bodyResponse.Code)
	}
	w := httptest.NewRecorder()
	jsonResponse(w, map[string]string{"value": strings.Repeat("x", maxJSONResponseBytes)})
	if w.Code != http.StatusServiceUnavailable || len(w.Body.Bytes()) > 100 {
		t.Fatalf("oversized JSON status=%d bytes=%d", w.Code, len(w.Body.Bytes()))
	}
}

func TestDashboardRejectsMappedAllowAllPolicies(t *testing.T) {
	for _, cfg := range []config.WebConfig{
		{AllowedIPs: []string{"::ffff:0.0.0.0/96"}},
		{AllowedIPs: []string{"127.0.0.1"}, TrustedProxies: []string{"::ffff:0.0.0.0/96"}},
	} {
		if _, err := New(cfg, fixtureSource{}, nil, nil); err == nil {
			t.Fatal("mapped allow-all policy accepted")
		}
	}
}
