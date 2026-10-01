package phpfpm

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func response(request *http.Request, code int, body string) *http.Response {
	return &http.Response{
		StatusCode: code, Header: make(http.Header),
		Body: io.NopCloser(strings.NewReader(body)), Request: request,
	}
}

func TestPollKeepsLastGoodSampleWhenPoolFails(t *testing.T) {
	var calls atomic.Int32
	collector := New(config.PHPFPMConfig{
		Interval: config.Duration{Duration: time.Second},
		Pools:    []config.PHPFPMPoolConfig{{Name: "site1", StatusURL: "http://127.0.0.1/status"}},
	})
	defer collector.Close()
	collector.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if !request.URL.Query().Has("json") {
			t.Error("collector did not request JSON")
		}
		if calls.Add(1) == 2 {
			return response(request, http.StatusServiceUnavailable, "unavailable"), nil
		}
		return response(request, http.StatusOK, `{"pool":"www","active processes":7,"idle processes":3,"total processes":10,"max active processes":9,"max children reached":1,"slow requests":2,"listen queue":0}`), nil
	})
	start := time.Unix(1000, 0)
	first := collector.Poll(context.Background(), start)[0]
	if first.Stale || first.LastError != "" || first.Stats == nil || *first.Stats.ActiveProcesses != 7 || *first.Stats.MaxChildrenReached != 1 {
		t.Fatalf("first PHP-FPM state: %+v", first)
	}
	failed := collector.Poll(context.Background(), start.Add(time.Second))[0]
	if !failed.Stale || failed.LastError == "" || failed.Stats == nil || *failed.Stats.ActiveProcesses != 7 || failed.SampledAt != start {
		t.Fatalf("failed poll should retain stale sample: %+v", failed)
	}
	recovered := collector.Poll(context.Background(), start.Add(2*time.Second))[0]
	if recovered.Stale || recovered.LastError != "" || recovered.SampledAt != start.Add(2*time.Second) {
		t.Fatalf("recovered poll: %+v", recovered)
	}
	if !collector.States(start.Add(5 * time.Second))[0].Stale {
		t.Fatal("old PHP-FPM sample was not marked stale")
	}
}

func TestRejectsOversizeAndRedirectResponses(t *testing.T) {
	collector := New(config.PHPFPMConfig{})
	defer collector.Close()
	collector.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/redirect" {
			result := response(request, http.StatusFound, "")
			result.Header.Set("Location", "http://example.invalid/")
			return result, nil
		}
		return response(request, http.StatusOK, strings.Repeat("x", maxStatusBytes+1)), nil
	})
	for _, path := range []string{"/oversize", "/redirect"} {
		if _, err := collector.fetch(context.Background(), "http://127.0.0.1"+path); err == nil {
			t.Fatalf("expected %s response to be rejected", path)
		}
	}
}
