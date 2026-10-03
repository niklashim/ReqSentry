// Package correlation attaches bounded error context without changing scores.
package correlation

import (
	"net/netip"
	"sync"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/model"
)

type Request struct {
	At              time.Time
	Site            string
	IP              netip.Addr
	Path, ID, Trace string
}
type Engine struct {
	mu          sync.RWMutex
	cfg         config.CorrelationConfig
	requestNext int
	errorNext   int
	requests    []Request
	errors      []model.ErrorEvent
	dropped     uint64
	configured  bool
}

func New(c config.CorrelationConfig, configured bool) *Engine {
	if c.MaxEvents == 0 {
		c.MaxEvents = 4096
	}
	if c.Window.Duration == 0 {
		c.Window.Duration = time.Minute
	}
	return &Engine{cfg: c, configured: configured}
}
func (e *Engine) Observe(r model.RequestEvent) {
	if !e.configured {
		return
	}
	if len(r.Path) > 256 {
		r.Path = ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	value := Request{r.Timestamp, r.SiteID, r.ClientIP, r.Path, r.RequestID, r.TraceID}
	if len(e.requests) < e.cfg.MaxEvents {
		e.requests = append(e.requests, value)
	} else {
		e.requests[e.requestNext] = value
		e.requestNext = (e.requestNext + 1) % len(e.requests)
		e.dropped++
	}
}
func (e *Engine) ObserveError(r model.ErrorEvent) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.errors) < e.cfg.MaxEvents {
		e.errors = append(e.errors, r)
	} else {
		e.errors[e.errorNext] = r
		e.errorNext = (e.errorNext + 1) % len(e.errors)
		e.dropped++
	}
}
func (e *Engine) Prune(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cutoff := now.Add(-e.cfg.Window.Duration - 2*time.Minute)
	expiredRequests := false
	for _, r := range e.requests {
		if r.At.Before(cutoff) {
			expiredRequests = true
			break
		}
	}
	if expiredRequests {
		rs := make([]Request, 0, len(e.requests))
		for j := 0; j < len(e.requests); j++ {
			r := e.requests[ringIndex(j, len(e.requests), e.requestNext, e.cfg.MaxEvents)]
			if !r.At.Before(cutoff) {
				rs = append(rs, r)
			}
		}
		e.requests = rs
		e.requestNext = 0
	}
	expiredErrors := false
	for _, r := range e.errors {
		if r.Timestamp.Before(cutoff) {
			expiredErrors = true
			break
		}
	}
	if expiredErrors {
		es := make([]model.ErrorEvent, 0, len(e.errors))
		for j := 0; j < len(e.errors); j++ {
			r := e.errors[ringIndex(j, len(e.errors), e.errorNext, e.cfg.MaxEvents)]
			if !r.Timestamp.Before(cutoff) {
				es = append(es, r)
			}
		}
		e.errors = es
		e.errorNext = 0
	}
}
func (e *Engine) Context(i model.Incident) *model.ErrorContext {
	e.mu.RLock()
	defer e.mu.RUnlock()
	c := &model.ErrorContext{Categories: map[string]int{}, Associations: map[string]int{}, Samples: []model.ErrorMatch{}, Coverage: "bounded observed errors; associations do not establish causation", Dropped: e.dropped}
	if !e.configured {
		c.Coverage = "no error source configured"
		return c
	}
	ids := map[string]bool{}
	traces := map[string]bool{}
	paths := map[string]bool{}
	conflicting := map[string]bool{}
	owners := map[string]netip.Addr{}
	for j := 0; j < len(e.requests); j++ {
		r := e.requests[ringIndex(j, len(e.requests), e.requestNext, e.cfg.MaxEvents)]
		if r.At.Before(i.WindowStart) || r.At.After(i.WindowEnd) || (i.SiteID != "" && r.Site != i.SiteID) {
			continue
		}
		if r.ID != "" {
			key := r.Site + ":" + r.ID
			if prior, ok := owners[key]; ok && prior != r.IP {
				conflicting[key] = true
			}
			owners[key] = r.IP
		}
		if r.IP == i.ClientIP {
			if r.ID != "" {
				ids[r.Site+":"+r.ID] = true
			}
			if r.Trace != "" {
				traces[r.Site+":"+r.Trace] = true
			}
			if len(paths) < 64 {
				paths[r.Site+":"+r.Path] = true
			}
		}
	}
	for j := 0; j < len(e.errors); j++ {
		r := e.errors[ringIndex(j, len(e.errors), e.errorNext, e.cfg.MaxEvents)]
		if r.Timestamp.Before(i.WindowStart.Add(-e.cfg.Window.Duration)) || r.Timestamp.After(i.WindowEnd) || (i.SiteID != "" && r.SiteID != "" && r.SiteID != i.SiteID) {
			continue
		}
		method := "site_time"
		uncertain := true
		if r.SiteID == "" {
			method = "server_time"
		} else if r.RequestID != "" && ids[r.SiteID+":"+r.RequestID] && !conflicting[r.SiteID+":"+r.RequestID] {
			method = "request_id"
			uncertain = false
		} else if r.TraceID != "" && traces[r.SiteID+":"+r.TraceID] {
			method = "trace_id"
		} else if r.ClientIP.IsValid() && r.ClientIP == i.ClientIP && r.Path != "" && paths[r.SiteID+":"+r.Path] {
			method = "logged_client_path_time"
		}
		c.Observed++
		category := r.Category
		if _, ok := c.Categories[category]; !ok && len(c.Categories) >= 64 {
			category = "other"
		}
		c.Categories[category]++
		c.Associations[method]++
		if len(c.Samples) < 8 {
			c.Samples = append(c.Samples, model.ErrorMatch{Event: r, Method: method, Uncertain: uncertain})
		}
	}
	return c
}
func (e *Engine) Recent(site string, from, to time.Time, limit int) []model.ErrorEvent {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if limit < 1 || limit > 50 {
		limit = 20
	}
	out := []model.ErrorEvent{}
	for j := len(e.errors) - 1; j >= 0 && len(out) < limit; j-- {
		r := e.errors[ringIndex(j, len(e.errors), e.errorNext, e.cfg.MaxEvents)]
		if !r.Timestamp.Before(from) && !r.Timestamp.After(to) && (site == "" || r.SiteID == site) {
			out = append(out, r)
		}
	}
	return out
}

func (e *Engine) MarkDropped() { e.mu.Lock(); e.dropped++; e.mu.Unlock() }

// Reset discards a failed recovery's partial warm state before live ingestion.
func (e *Engine) Reset() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.requests, e.errors = nil, nil
	e.requestNext, e.errorNext, e.dropped = 0, 0, 0
}

func ringIndex(j, length, next, capacity int) int {
	if length == capacity {
		return (next + j) % length
	}
	return j
}
