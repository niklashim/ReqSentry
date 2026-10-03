package phpfpm

import (
	"context"
	"fmt"
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
	collector.now = func() time.Time { return start }
	first := collector.Poll(context.Background(), start)[0]
	if first.Stale || first.LastError != "" || first.Stats == nil || *first.Stats.ActiveProcesses != 7 || *first.Stats.MaxChildrenReached != 1 {
		t.Fatalf("first PHP-FPM state: %+v", first)
	}
	sampleTime := start.Add(time.Second)
	collector.now = func() time.Time { return sampleTime }
	failed := collector.Poll(context.Background(), sampleTime)[0]
	if !failed.Stale || failed.LastError == "" || failed.Stats == nil || *failed.Stats.ActiveProcesses != 7 || failed.SampledAt != start {
		t.Fatalf("failed poll should retain stale sample: %+v", failed)
	}
	sampleTime = start.Add(2 * time.Second)
	recovered := collector.Poll(context.Background(), sampleTime)[0]
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

func TestSlowPoolsDoNotAgeFreshHealthySamples(t *testing.T) {
	for _, healthyFirst := range []bool{true, false} {
		t.Run(fmt.Sprint(healthyFirst), func(t *testing.T) {
			cfg := config.PHPFPMConfig{Interval: config.Duration{Duration: time.Second}}
			for i := range 16 {
				path := "slow"
				if (healthyFirst && i == 0) || (!healthyFirst && i == 15) {
					path = "healthy"
				}
				cfg.Pools = append(cfg.Pools, config.PHPFPMPoolConfig{Name: fmt.Sprint(i), StatusURL: "http://127.0.0.1/" + path})
			}
			c := New(cfg)
			defer c.Close()
			var active, peak atomic.Int32
			c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
				n := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
				}
				if r.URL.Path == "/slow" {
					select {
					case <-time.After(150 * time.Millisecond):
					case <-r.Context().Done():
						return nil, r.Context().Err()
					}
					return response(r, 503, "unavailable"), nil
				}
				return response(r, 200, `{"active processes":1,"idle processes":2,"total processes":3}`), nil
			})
			start := time.Now()
			states := c.Poll(context.Background(), start)
			index := 15
			if healthyFirst {
				index = 0
			}
			state := states[index]
			if state.Stale || state.Stats == nil || state.SampledAt.Before(start) || state.SampledAt.After(time.Now()) {
				t.Fatalf("healthy sample=%+v", state)
			}
			if peak.Load() > 16 || peak.Load() < 2 {
				t.Fatalf("poll concurrency=%d", peak.Load())
			}
			for i, s := range states {
				if i != index && (!s.Stale || s.LastError == "") {
					t.Fatal("failed pool reported fresh")
				}
			}
		})
	}
}

func TestPoolTimeoutsCannotMakeHealthyEndpointsImmediatelyStale(t *testing.T) {
	cfg := config.PHPFPMConfig{Interval: config.Duration{Duration: 50 * time.Millisecond}}
	for i := range 16 {
		path := "slow"
		if i == 0 || i == 15 {
			path = "healthy"
		}
		cfg.Pools = append(cfg.Pools, config.PHPFPMPoolConfig{Name: fmt.Sprint(i), StatusURL: "http://127.0.0.1/" + path})
	}
	c := New(cfg)
	defer c.Close()
	c.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return nil, r.Context().Err()
		}
		return response(r, 200, `{"active processes":1,"idle processes":2,"total processes":3}`), nil
	})
	states := c.Poll(context.Background(), time.Now())
	for _, i := range []int{0, 15} {
		if states[i].Stale || states[i].Stats == nil {
			t.Fatalf("healthy endpoint queued behind failures: %+v", states[i])
		}
	}
	for i := 1; i < 15; i++ {
		if !states[i].Stale || states[i].LastError == "" {
			t.Fatal("timed out endpoint reported fresh")
		}
	}
}
