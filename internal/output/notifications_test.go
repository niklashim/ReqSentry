package output

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/aws/smithy-go"
)

type fakeSNS struct {
	input *sns.PublishInput
	err   error
}

func (f *fakeSNS) Publish(_ context.Context, p *sns.PublishInput, _ ...func(*sns.Options)) (*sns.PublishOutput, error) {
	f.input = p
	id := "ack"
	return &sns.PublishOutput{MessageId: &id}, f.err
}
func TestSNSUsesJSONBodyAndFilterAttributes(t *testing.T) {
	f := &fakeSNS{}
	send := snsSender(f, config.DestinationConfig{TopicARN: "arn:aws:sns:eu-west-1:123456789012:alerts"})
	e := Notification{Version: 1, ID: "stable", Kind: "incident", MonitorOnly: true, Incident: &model.Incident{SiteID: "shop", Decision: model.DecisionWouldBlock, MonitorOnly: true}}
	ack, err := send(context.Background(), e)
	if err != nil || ack != "ack" || f.input.MessageStructure != nil || *f.input.MessageAttributes["site"].StringValue != "shop" {
		t.Fatalf("invalid publish: %+v %v", f.input, err)
	}
	f.err = errors.New("https://secret.example?token=bad")
	_, err = send(context.Background(), e)
	if err == nil || err.Error() == f.err.Error() {
		t.Fatal("SNS failure leaked transport detail")
	}
}
func TestRoutingCooldownAndIndependentFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	delivered := 0
	makeDestination := func(name string, fail bool) *destination {
		d := &destination{cfg: config.DestinationConfig{Name: name, Sites: []string{"shop"}, MinimumScore: 80, QueueSize: 2, MaxAttempts: 1, MaxAge: config.Duration{Duration: time.Second}, Cooldown: config.Duration{Duration: time.Minute}}, queue: make(chan Notification, 2), last: map[string]time.Time{}, ctx: ctx, cancel: cancel, done: make(chan struct{})}
		d.send = func(context.Context, Notification) (string, error) {
			if fail {
				return "", deliveryError{reason: "failed"}
			}
			mu.Lock()
			delivered++
			mu.Unlock()
			return "ok", nil
		}
		go d.run()
		return d
	}
	n := &Notifications{destinations: []*destination{makeDestination("bad", true), makeDestination("good", false)}, logger: log.New(io.Discard, "", 0)}
	i := model.Incident{Server: "server", SiteID: "shop", ClientIP: netip.MustParseAddr("192.0.2.1"), Score: 90, Decision: model.DecisionWouldBlock, Timestamp: time.Now()}
	if err := n.WriteIncident(ctx, i); err != nil {
		t.Fatal(err)
	}
	_ = n.WriteIncident(ctx, i)
	i.SiteID = "other"
	_ = n.WriteIncident(ctx, i)
	n.Close()
	mu.Lock()
	defer mu.Unlock()
	if delivered != 1 {
		t.Fatalf("delivered=%d", delivered)
	}
	states := n.Status()
	if states[0].Failed != 1 || states[1].Delivered != 1 || states[1].Suppressed != 2 {
		t.Fatalf("incorrect status %+v", states)
	}
}

func TestTeamsCardsAndRedactedThrottling(t *testing.T) {
	var payload map[string]any
	client := &http.Client{Transport: slackTransport(func(r *http.Request) (*http.Response, error) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		return &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"5"}}, Body: io.NopCloser(strings.NewReader("secret-response"))}, nil
	})}
	send := webhookSender(config.DestinationConfig{Type: "teams"}, "https://test.logic.azure.com/path?sig=SECRET", client)
	_, err := send(context.Background(), Notification{Kind: "test", Detail: "@everyone test <at>"})
	var failure deliveryError
	if !errors.As(err, &failure) || !failure.retry || failure.after != 5*time.Second {
		t.Fatalf("retry handling %v", err)
	}
	b, _ := json.Marshal(payload)
	if !strings.Contains(string(b), "application/vnd.microsoft.card.adaptive") || strings.Contains(string(b), "@everyone") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("unsafe Teams payload %s %v", b, err)
	}
}

func TestSNSBudgetStackPrivacyAndPermanentErrors(t *testing.T) {
	f := &fakeSNS{}
	send := snsSender(f, config.DestinationConfig{TopicARN: "arn:aws:sns:eu-west-1:123456789012:alerts"})
	incident := &model.Incident{EventID: "stable", SiteID: "shop", MonitorOnly: true, Signals: []model.Signal{{Code: "HIGH_RATE", Evidence: map[string]any{"sample": strings.Repeat("x", 300<<10)}}}, Errors: &model.ErrorContext{Samples: []model.ErrorMatch{{Event: model.ErrorEvent{StackTrace: "PRIVATE STACK", Message: "AUDIT_SECRET"}}}}}
	e := Notification{Version: 1, ID: "stable", Kind: "incident", Server: "test", MonitorOnly: true, Incident: incident}
	if _, err := send(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	var body Notification
	if err := json.Unmarshal([]byte(*f.input.Message), &body); err != nil || !body.Truncated || body.ID != "stable" || len(*f.input.Message) > 250<<10 || strings.Contains(*f.input.Message, "PRIVATE STACK") || strings.Contains(*f.input.Message, "AUDIT_SECRET") {
		t.Fatalf("unsafe budget handling %+v %v", body, err)
	}
	if incident.Errors.Samples[0].Event.StackTrace != "PRIVATE STACK" || incident.Signals[0].Evidence == nil {
		t.Fatal("remote trimming mutated saved evidence")
	}
	for _, err := range []error{&smithy.GenericAPIError{Code: "AuthorizationError", Message: "SECRET", Fault: smithy.FaultClient}, deliveryError{reason: "credentials unavailable"}} {
		f.err = err
		_, err = send(context.Background(), e)
		var failure deliveryError
		if !errors.As(err, &failure) || failure.retry || strings.Contains(err.Error(), "SECRET") {
			t.Fatalf("permanent error retried or leaked: %v", err)
		}
	}
	if text := safeText(strings.Repeat("日", 3000), 6000); !utf8.ValidString(text) || !strings.Contains(text, "[truncated]") {
		t.Fatal("unsafe UTF-8 truncation")
	}
}

func TestNotificationQueueAgeRetryIdentityAndExhaustion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &destination{cfg: config.DestinationConfig{QueueSize: 1, MaxAttempts: 2, MaxAge: config.Duration{Duration: 5 * time.Second}, Cooldown: config.Duration{Duration: time.Minute}}, queue: make(chan Notification, 1), last: map[string]time.Time{}, ctx: ctx}
	e := Notification{ID: "same-on-retry", queuedAt: time.Now()}
	if err := d.enqueue("first", e); err != nil {
		t.Fatal(err)
	}
	if err := d.enqueue("second", e); err == nil || d.status.Dropped != 1 {
		t.Fatal("full queue not reported")
	}
	calls := 0
	d.send = func(_ context.Context, got Notification) (string, error) {
		calls++
		if got.ID != e.ID {
			t.Fatal("retry changed event identity")
		}
		return "", deliveryError{retry: true, reason: "temporary"}
	}
	d.deliver(e)
	if calls != 2 || d.status.Retried != 1 || d.status.Failed != 1 {
		t.Fatalf("retry budget not respected calls=%d status=%+v", calls, d.status)
	}
	e.queuedAt = time.Now().Add(-time.Minute)
	d.deliver(e)
	if calls != 2 || d.status.Dropped != 2 {
		t.Fatal("expired message was sent")
	}
}
