package output

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sns/types"
	"github.com/aws/smithy-go"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

type Notification struct {
	queuedAt    time.Time
	Version     int             `json:"version"`
	ID          string          `json:"event_id"`
	Kind        string          `json:"event_kind"`
	Server      string          `json:"server"`
	Site        string          `json:"site,omitempty"`
	Timestamp   time.Time       `json:"timestamp"`
	MonitorOnly bool            `json:"monitor_only"`
	Incident    *model.Incident `json:"incident,omitempty"`
	Operation   string          `json:"operation,omitempty"`
	Detail      string          `json:"detail,omitempty"`
	Truncated   bool            `json:"truncated,omitempty"`
}
type DeliveryStatus struct {
	Name           string     `json:"name"`
	Type           string     `json:"type"`
	State          string     `json:"state"`
	Queued         int        `json:"queued"`
	Delivered      uint64     `json:"delivered"`
	Retried        uint64     `json:"retried"`
	Suppressed     uint64     `json:"suppressed"`
	Dropped        uint64     `json:"dropped"`
	Failed         uint64     `json:"failed"`
	LastAccepted   *time.Time `json:"last_accepted,omitempty"`
	Acknowledgment string     `json:"acknowledgment,omitempty"`
}
type deliveryError struct {
	retry  bool
	after  time.Duration
	reason string
}

func (e deliveryError) Error() string { return e.reason }

type sender func(context.Context, Notification) (string, error)
type destination struct {
	cfg    config.DestinationConfig
	send   sender
	mu     sync.Mutex
	status DeliveryStatus
	queue  chan Notification
	last   map[string]time.Time
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	closed bool
}
type Notifications struct {
	destinations []*destination
	logger       *log.Logger
	server       string
}

func NewNotifications(cfg []config.DestinationConfig, logger *log.Logger, server string) *Notifications {
	n := &Notifications{logger: logger, server: server}
	for _, c := range cfg {
		if !c.Enabled {
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		d := &destination{cfg: c, ctx: ctx, cancel: cancel, queue: make(chan Notification, c.QueueSize), last: map[string]time.Time{}, done: make(chan struct{}), status: DeliveryStatus{Name: c.Name, Type: c.Type, State: "ready"}}
		send, err := newSender(c)
		d.send = send
		if err != nil {
			d.status.State = "unavailable"
			logger.Printf("notification destination unavailable name=%s type=%s", c.Name, c.Type)
		}
		n.destinations = append(n.destinations, d)
		go d.run()
	}
	return n
}
func notificationID(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16])
}
func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func (n *Notifications) WriteIncident(_ context.Context, i model.Incident) error {
	codes := make([]string, 0, len(i.Signals))
	for _, s := range i.Signals {
		codes = append(codes, s.Code)
	}
	sort.Strings(codes)
	event := Notification{Version: 1, Kind: "incident", Server: i.Server, Site: i.SiteID, Timestamp: i.Timestamp, MonitorOnly: true, Incident: &i}
	event.ID = notificationID([]any{i.Server, i.SiteID, i.ClientIP.String(), i.WindowStart, i.WindowEnd, i.RulesetVersion, codes})
	if i.EventID != "" {
		event.ID = i.EventID
	}
	key := "incident:" + i.Server + ":" + i.SiteID + ":" + i.ClientIP.String() + ":" + strings.Join(codes, ",")
	var errs []error
	for _, d := range n.destinations {
		c := d.cfg
		if i.Score < c.MinimumScore || (len(c.Sites) > 0 && !containsString(c.Sites, i.SiteID)) || (len(c.Decisions) > 0 && !containsString(c.Decisions, string(i.Decision))) {
			d.mu.Lock()
			d.status.Suppressed++
			d.mu.Unlock()
			continue
		}
		if err := d.enqueue(key, event); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func (n *Notifications) Operational(kind, detail string, count uint64) error {
	if count < 3 || kind == "incident_output" || strings.HasPrefix(kind, "notification") {
		return nil
	}
	// Operational error strings can contain URLs and secrets. Publish only the source kind and recurrence count.
	event := Notification{Version: 1, Kind: "operational", Server: n.server, Timestamp: time.Now().UTC(), MonitorOnly: true, Operation: safeText(kind, 128), Detail: fmt.Sprintf("repeated failures=%d; inspect local diagnostics", count)}
	event.ID = notificationID([]any{event.Operation, event.Timestamp})
	for _, d := range n.destinations {
		if d.cfg.Operational {
			_ = d.enqueue("operation:"+kind, event)
		}
	}
	return nil
}
func (n *Notifications) Test(ctx context.Context, name string) error {
	for _, d := range n.destinations {
		if d.cfg.Name == name {
			if d.send == nil {
				return errors.New("destination unavailable")
			}
			e := Notification{Version: 1, Kind: "test", Server: n.server, Timestamp: time.Now().UTC(), MonitorOnly: true, Detail: "SYNTHETIC TEST — MONITOR MODE — NO ACTION WAS TAKEN"}
			e.ID = notificationID(e.Timestamp)
			_, err := d.send(ctx, e)
			return err
		}
	}
	return errors.New("enabled destination not found")
}
func (n *Notifications) Status() []DeliveryStatus {
	result := make([]DeliveryStatus, 0, len(n.destinations))
	for _, d := range n.destinations {
		d.mu.Lock()
		s := d.status
		s.Queued = len(d.queue)
		d.mu.Unlock()
		result = append(result, s)
	}
	return result
}
func (d *destination) enqueue(key string, e Notification) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return errors.New("notification output closed")
	}
	now := time.Now()
	if at, ok := d.last[key]; ok && now.Sub(at) < d.cfg.Cooldown.Duration {
		d.status.Suppressed++
		return nil
	}
	select {
	case d.queue <- func() Notification { e.queuedAt = now; return e }():
		if len(d.last) >= 4096 {
			for k, at := range d.last {
				if now.Sub(at) >= d.cfg.Cooldown.Duration {
					delete(d.last, k)
				}
			}
			if len(d.last) >= 4096 {
				d.last = map[string]time.Time{}
			}
		}
		d.last[key] = now
		return nil
	default:
		d.status.Dropped++
		return errors.New("notification queue full")
	}
}
func (d *destination) run() {
	defer close(d.done)
	for {
		select {
		case <-d.ctx.Done():
			return
		case e, ok := <-d.queue:
			if !ok {
				return
			}
			if d.send == nil {
				d.mu.Lock()
				d.status.Failed++
				d.mu.Unlock()
				continue
			}
			d.deliver(e)
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-d.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
		}
	}
}
func (d *destination) deliver(e Notification) {
	queued := e.queuedAt
	if queued.IsZero() {
		queued = time.Now()
	}
	deadline := queued.Add(d.cfg.MaxAge.Duration)
	if time.Now().After(deadline) {
		d.mu.Lock()
		d.status.Dropped++
		d.mu.Unlock()
		return
	}
	var err error
	for attempt := 0; attempt < d.cfg.MaxAttempts; attempt++ {
		ctx, cancel := context.WithDeadline(d.ctx, deadline)
		ack, sendErr := d.send(ctx, e)
		cancel()
		err = sendErr
		if err == nil {
			at := time.Now().UTC()
			d.mu.Lock()
			d.status.Delivered++
			d.status.LastAccepted = &at
			d.status.Acknowledgment = ack
			d.status.State = "ready"
			d.mu.Unlock()
			return
		}
		var failure deliveryError
		if !errors.As(err, &failure) || !failure.retry || attempt+1 == d.cfg.MaxAttempts {
			break
		}
		delay := time.Duration(1<<attempt)*time.Second + time.Duration(rand.IntN(500))*time.Millisecond
		if failure.after > delay {
			delay = failure.after
		}
		if time.Now().Add(delay).After(deadline) {
			break
		}
		d.mu.Lock()
		d.status.Retried++
		d.mu.Unlock()
		timer := time.NewTimer(delay)
		select {
		case <-d.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
	d.mu.Lock()
	d.status.Failed++
	d.status.State = "delivery_failed"
	d.mu.Unlock()
}
func (n *Notifications) Close() {
	for _, d := range n.destinations {
		d.mu.Lock()
		if !d.closed {
			d.closed = true
			close(d.queue)
		}
		d.mu.Unlock()
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for _, d := range n.destinations {
		select {
		case <-d.done:
		case <-deadline.C:
			for _, other := range n.destinations {
				other.cancel()
			}
			for _, other := range n.destinations {
				<-other.done
			}
			return
		}
	}
	for _, d := range n.destinations {
		d.cancel()
	}
}
func safeText(s string, limit int) string {
	s = strings.NewReplacer("\r", " ", "\n", " ", "<", "", ">", "", "@", "＠").Replace(s)
	if len(s) > limit {
		s = s[:limit]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
		s += "… [truncated]"
	}
	return s
}

func newSender(c config.DestinationConfig) (sender, error) {
	if c.Type == "sns" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(c.Region)}
		if c.Profile != "" {
			opts = append(opts, awsconfig.WithSharedConfigProfile(c.Profile))
		}
		cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
		if err != nil {
			return nil, errors.New("AWS configuration unavailable")
		}
		if cfg.Credentials != nil {
			cfg.Credentials = permanentCredentialErrors{cfg.Credentials}
		}
		client := sns.NewFromConfig(cfg, func(o *sns.Options) { o.RetryMaxAttempts = 1 })
		return snsSender(client, c), nil
	}
	secret, err := config.ResolveSecret(c.WebhookEnv, c.WebhookCredential)
	if err != nil {
		return nil, errors.New("webhook credential unavailable")
	}
	u, err := url.Parse(secret)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Port() != "" {
		return nil, errors.New("invalid webhook endpoint")
	}
	host := strings.ToLower(u.Hostname())
	valid := false
	if c.Type == "slack" {
		valid = (host == "hooks.slack.com" || host == "hooks.slack-gov.com") && strings.HasPrefix(u.Path, "/services/")
	} else {
		valid = (strings.HasSuffix(host, ".logic.azure.com") || strings.HasSuffix(host, ".environment.api.powerplatform.com")) && u.RawQuery != ""
	}
	if !valid {
		return nil, errors.New("unsupported webhook endpoint host")
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("webhook redirects rejected") }}
	return webhookSender(c, secret, client), nil
}

func webhookSender(c config.DestinationConfig, secret string, client *http.Client) sender {
	return func(ctx context.Context, e Notification) (string, error) {
		text := e.Detail
		if e.Incident != nil {
			codes := []string{}
			for _, s := range e.Incident.Signals {
				codes = append(codes, s.Code)
			}
			text = formatIncident(*e.Incident, codes)
		} else if e.Kind == "operational" {
			text = "ReqSentry operational issue | server=" + safeText(e.Server, 80) + " | " + e.Operation + " | " + e.Detail + " | MONITOR MODE — NO ACTION WAS TAKEN"
		}
		text = safeText(text, 6000)
		var payload any = map[string]any{"text": text}
		if c.Type == "teams" {
			body := []any{map[string]any{"type": "TextBlock", "text": text, "wrap": true}}
			if c.DashboardURL != "" {
				body = append(body, map[string]any{"type": "TextBlock", "text": "[Open ReqSentry dashboard](" + c.DashboardURL + ")", "wrap": true})
			}
			payload = map[string]any{"type": "message", "attachments": []any{map[string]any{"contentType": "application/vnd.microsoft.card.adaptive", "content": map[string]any{"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.2", "body": body}}}}
		}
		b, err := json.Marshal(payload)
		if err != nil || len(b) > 24<<10 {
			return "", deliveryError{reason: "payload exceeds budget"}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, secret, bytes.NewReader(b))
		if err != nil {
			return "", deliveryError{reason: "invalid webhook request"}
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return "", deliveryError{retry: true, reason: "webhook transport failed"}
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return "HTTP accepted", nil
		}
		after := time.Duration(0)
		if sec, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
			after = time.Duration(sec) * time.Second
		} else if at, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
			after = time.Until(at)
		}
		return "", deliveryError{retry: resp.StatusCode == 429 || resp.StatusCode >= 500, after: after, reason: fmt.Sprintf("webhook HTTP %d", resp.StatusCode)}
	}
}

type snsPublisher interface {
	Publish(context.Context, *sns.PublishInput, ...func(*sns.Options)) (*sns.PublishOutput, error)
}

type permanentCredentialErrors struct{ aws.CredentialsProvider }

func (p permanentCredentialErrors) Retrieve(ctx context.Context) (aws.Credentials, error) {
	credentials, err := p.CredentialsProvider.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, deliveryError{reason: "AWS credentials unavailable"}
	}
	return credentials, nil
}

func snsSender(client snsPublisher, c config.DestinationConfig) sender {
	return func(ctx context.Context, e Notification) (string, error) {
		attrs := map[string]types.MessageAttributeValue{"event_kind": {DataType: aws.String("String"), StringValue: aws.String(e.Kind)}}
		if e.Incident != nil {
			site := e.Incident.SiteID
			if site == "" {
				site = "all-sites"
			}
			attrs["site"] = types.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(site)}
			attrs["decision"] = types.MessageAttributeValue{DataType: aws.String("String"), StringValue: aws.String(string(e.Incident.Decision))}
		}
		if e.Incident != nil && e.Incident.Errors != nil {
			copy := *e.Incident
			ctx := *copy.Errors
			ctx.Samples = append([]model.ErrorMatch(nil), ctx.Samples...)
			for i := range ctx.Samples {
				ctx.Samples[i].Event.StackTrace = ""
				// Remote notifications carry correlation metadata, never arbitrary
				// application diagnostics (which may contain unrecognized secrets).
				ctx.Samples[i].Event.Message = ""
			}
			copy.Errors = &ctx
			e.Incident = &copy
		}
		b, err := json.Marshal(e)
		if err != nil {
			return "", deliveryError{reason: "invalid SNS payload"}
		}
		if len(b) > 250<<10 && e.Incident != nil {
			copy := *e.Incident
			copy.Signals = append([]model.Signal(nil), copy.Signals...)
			for i := range copy.Signals {
				copy.Signals[i].Evidence = nil
			}
			e.Incident = &copy
			e.Truncated = true
			b, err = json.Marshal(e)
		}
		if err != nil || len(b) > 250<<10 {
			return "", deliveryError{reason: "SNS payload exceeds budget"}
		}
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		result, err := client.Publish(ctx, &sns.PublishInput{TopicArn: aws.String(c.TopicARN), Message: aws.String(string(b)), MessageAttributes: attrs})
		if err != nil {
			var credentialFailure deliveryError
			if errors.As(err, &credentialFailure) {
				return "", credentialFailure
			}
			var api smithy.APIError
			if errors.As(err, &api) {
				retry := api.ErrorFault() == smithy.FaultServer || strings.Contains(strings.ToLower(api.ErrorCode()), "throttl")
				return "", deliveryError{retry: retry, reason: "SNS publish rejected"}
			}
			return "", deliveryError{retry: true, reason: "SNS transport or credentials unavailable"}
		}
		return safeText(aws.ToString(result.MessageId), 128), nil
	}
}
