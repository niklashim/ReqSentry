package output

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

var ErrSlackQueueFull = errors.New("Slack alert queue full")

type slackMessage struct {
	Text string `json:"text"`
}

// Slack queues short, monitor-only alerts. All HTTP work is on a separate
// worker and the queue has a fixed capacity.
type Slack struct {
	webhook  string
	config   config.SlackOutputConfig
	client   *http.Client
	logger   *log.Logger
	queue    chan slackMessage
	done     chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	closed   bool
	last     map[string]time.Time
	failures uint64
}

func NewSlack(cfg config.SlackOutputConfig, logger *log.Logger) (*Slack, error) {
	secret, err := config.ResolveSecret(cfg.WebhookEnv, cfg.WebhookCredential)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(secret)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || (parsed.Hostname() != "hooks.slack.com" && parsed.Hostname() != "hooks.slack-gov.com") || !strings.HasPrefix(parsed.Path, "/services/") {
		return nil, errors.New("Slack webhook must be an HTTPS incoming webhook URL")
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Slack{webhook: secret, config: cfg, client: &http.Client{Timeout: 5 * time.Second}, logger: logger, queue: make(chan slackMessage, 128), done: make(chan struct{}), ctx: ctx, cancel: cancel, last: make(map[string]time.Time)}
	s.client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= 3 || request.URL.Scheme != "https" || request.URL.Hostname() != parsed.Hostname() {
			return errors.New("Slack webhook redirect rejected")
		}
		return nil
	}
	go s.run()
	return s, nil
}

func (s *Slack) WriteIncident(_ context.Context, incident model.Incident) error {
	if incident.Score < s.config.MinimumScore {
		return nil
	}
	codes := make([]string, 0, len(incident.Signals))
	for _, signal := range incident.Signals {
		codes = append(codes, signal.Code)
	}
	sort.Strings(codes)
	key := "incident:" + incident.Server + ":" + incident.SiteID + ":" + incident.ClientIP.String() + ":" + strings.Join(codes, ",")
	return s.enqueue(key, incident.Timestamp, s.config.Cooldown.Duration, slackMessage{Text: formatIncident(incident, codes)})
}

// SlackIncidentText returns the same incident text used by outgoing Slack alerts.
func SlackIncidentText(incident model.Incident) string {
	codes := make([]string, 0, len(incident.Signals))
	for _, signal := range incident.Signals {
		codes = append(codes, signal.Code)
	}
	return formatIncident(incident, codes)
}

func formatIncident(incident model.Incident, codes []string) string {
	if len(codes) > 4 {
		codes = codes[:4]
	}
	site := incident.SiteID
	if site == "" {
		site = "All sites"
	}
	text := fmt.Sprintf("ReqSentry incident | server=%s site=%s ip=%s | window=%s–%s | requests=%d peak_rps=%d | evidence=%s | score=%d decision=%s",
		clip(incident.Server, 80), clip(site, 80), incident.ClientIP, incident.WindowStart.UTC().Format(time.RFC3339), incident.WindowEnd.UTC().Format(time.RFC3339), incident.Requests, incident.PeakRPS, strings.Join(codes, ","), incident.Score, incident.Decision)
	if incident.CPUPercent != nil {
		text += fmt.Sprintf(" | cpu=%.1f%%", *incident.CPUPercent)
	}
	if incident.ASN != nil {
		text += fmt.Sprintf(" | asn=%d", *incident.ASN)
	}
	if incident.EnrichmentStatus != "" {
		text += " | enrichment=" + clip(incident.EnrichmentStatus, 40)
	}
	return text + " | MONITOR MODE — NO ACTION WAS TAKEN"
}

func clip(value string, limit int) string {
	value = strings.NewReplacer("\n", " ", "\r", " ", "<", "", ">", "", "&", "").Replace(value)
	if len(value) > limit {
		value = value[:limit]
		for !utf8.ValidString(value) {
			value = value[:len(value)-1]
		}
		return value + "… [truncated]"
	}
	return value
}

// Operational failures are alerted only after recurrence; the same kind is
// then rate limited by the configured cooldown.
func (s *Slack) Operational(kind, detail string, consecutive uint64) error {
	if consecutive < 3 {
		return nil
	}
	return s.enqueue("operation:"+kind, time.Now(), s.config.Cooldown.Duration,
		slackMessage{Text: fmt.Sprintf("ReqSentry operational issue | %s | failures=%d | %s | MONITOR MODE — NO ACTION WAS TAKEN", clip(kind, 80), consecutive, clip(detail, 300))})
}

func (s *Slack) enqueue(key string, at time.Time, cooldown time.Duration, message slackMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("Slack output closed")
	}
	if at.IsZero() {
		at = time.Now()
	}
	if prior, ok := s.last[key]; ok && at.Sub(prior) < cooldown {
		return nil
	}
	select {
	case s.queue <- message:
		s.last[key] = at
		if len(s.last) > 4096 {
			for candidate, when := range s.last {
				if at.Sub(when) > cooldown {
					delete(s.last, candidate)
				}
			}
			if len(s.last) > 4096 {
				s.last = map[string]time.Time{key: at}
			}
		}
		return nil
	default:
		return ErrSlackQueueFull
	}
}

func (s *Slack) run() {
	defer close(s.done)
	for message := range s.queue {
		if s.ctx.Err() != nil {
			return
		}
		body, _ := json.Marshal(message)
		request, err := http.NewRequestWithContext(s.ctx, http.MethodPost, s.webhook, bytes.NewReader(body))
		if err == nil {
			request.Header.Set("Content-Type", "application/json")
			response, postErr := s.client.Do(request)
			err = postErr
			if err == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024))
				_ = response.Body.Close()
				if response.StatusCode < 200 || response.StatusCode >= 300 {
					err = fmt.Errorf("HTTP %d", response.StatusCode)
				}
			}
		}
		if err != nil {
			s.failures++
			if s.failures&(s.failures-1) == 0 {
				s.logger.Printf("Slack delivery failed failures=%d: %v", s.failures, err)
			}
		} else if s.failures > 0 {
			s.logger.Print("Slack delivery recovered")
			s.failures = 0
		}
	}
}

func (s *Slack) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		close(s.queue)
	}
	s.mu.Unlock()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		s.cancel()
		<-s.done
	}
	s.cancel()
}
