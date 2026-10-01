package output

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

type slackTransport func(*http.Request) (*http.Response, error)

func (f slackTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSlackIncidentCooldownAndOperationalThreshold(t *testing.T) {
	t.Setenv("REQSENTRY_TEST_SLACK", "https://hooks.slack.com/services/T/B/secret")
	cfg := config.SlackOutputConfig{Enabled: true, WebhookEnv: "REQSENTRY_TEST_SLACK", MinimumScore: 80, Cooldown: config.Duration{Duration: 10 * time.Minute}}
	s, err := NewSlack(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	var posted []string
	s.client.Transport = slackTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("invalid webhook request: %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		posted = append(posted, string(body))
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader([]byte("ok")))}, nil
	})
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	i := model.Incident{Timestamp: now, Server: "host", SiteID: "site", ClientIP: netip.MustParseAddr("2001:db8::1"), WindowStart: now.Add(-30 * time.Second), WindowEnd: now, Score: 90, Decision: model.DecisionWouldBlock, MonitorOnly: true, Signals: []model.Signal{{Code: "HIGH_404_RATE"}}}
	if err := s.WriteIncident(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if err := s.WriteIncident(context.Background(), i); err != nil {
		t.Fatal(err)
	}
	if err := s.Operational("input", "missing", 2); err != nil {
		t.Fatal(err)
	}
	if err := s.Operational("input", "missing", 3); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if len(posted) != 2 {
		t.Fatalf("posted=%d want 2", len(posted))
	}
	if !strings.Contains(posted[0], "MONITOR MODE — NO ACTION WAS TAKEN") || !strings.Contains(posted[0], "HIGH_404_RATE") || !strings.Contains(posted[0], "2001:db8::1") {
		t.Fatalf("incident message: %s", posted[0])
	}
	if !strings.Contains(posted[1], "operational issue") {
		t.Fatalf("operational message: %s", posted[1])
	}
}
