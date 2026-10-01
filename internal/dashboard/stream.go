package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// SSE is one-way, supported by browsers without a client library, and
// automatically reconnects. A single publisher builds each aggregate update.
type eventHub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
	last    []byte
}

func newEventHub() *eventHub { return &eventHub{clients: make(map[chan []byte]struct{})} }

func (h *eventHub) publish(payload []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.last = payload
	for client := range h.clients {
		select {
		case client <- payload:
		default:
			select {
			case <-client:
			default:
			}
			select {
			case client <- payload:
			default:
			}
		}
	}
}

func (s *Server) realtimeEnabled() bool {
	return s.config.Realtime.Enabled == nil || *s.config.Realtime.Enabled
}

func (s *Server) publishLoop(ctx context.Context) {
	interval := s.config.Realtime.Interval.Duration
	if interval < time.Second || interval > 10*time.Second {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	s.publish()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.publish()
		}
	}
}

func (s *Server) publish() {
	if s.source == nil {
		return
	}
	view := s.source.Dashboard(time.Minute, 20)
	view.TopIPs = nil
	view.SiteIPs = nil
	health, available := s.source.Health()
	payload, err := json.Marshal(map[string]any{
		"at": view.At, "server": s.source.ServerName(), "mode": "monitor",
		"analysis_active": s.source.DeepAnalysisActive(), "live": view,
		"health": health, "health_available": available,
		"php_fpm":                 s.source.PHPFPM(),
		"recent_incident_summary": summarizeIncidents(s.source.Incidents(), time.Now()),
	})
	if err != nil || len(payload) > 64<<10 {
		return
	}
	s.hub.publish(payload)
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/stream" {
		http.NotFound(w, r)
		return
	}
	if !s.realtimeEnabled() {
		http.Error(w, "live updates disabled", http.StatusServiceUnavailable)
		return
	}
	maximum := int64(s.config.Realtime.MaxClients)
	if maximum < 1 {
		maximum = 32
	}
	for {
		current := s.clients.Load()
		if current >= maximum {
			http.Error(w, "too many viewers", http.StatusServiceUnavailable)
			return
		}
		if s.clients.CompareAndSwap(current, current+1) {
			break
		}
	}
	s.setState(s.State().Status)
	defer func() { s.clients.Add(-1); s.setState(s.State().Status) }()
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Connection", "keep-alive")
	client := make(chan []byte, 1)
	s.hub.mu.Lock()
	s.hub.clients[client] = struct{}{}
	initial := s.hub.last
	s.hub.mu.Unlock()
	defer func() { s.hub.mu.Lock(); delete(s.hub.clients, client); s.hub.mu.Unlock() }()
	write := func(data []byte) bool {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := w.Write([]byte("event: snapshot\ndata: ")); err != nil {
			return false
		}
		if _, err := w.Write(data); err != nil {
			return false
		}
		if _, err := w.Write([]byte("\n\n")); err != nil {
			return false
		}
		return http.NewResponseController(w).Flush() == nil
	}
	if len(initial) > 0 && !write(initial) {
		return
	}
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case data := <-client:
			if !write(data) {
				return
			}
		case <-keepalive.C:
			_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err := w.Write([]byte(": keepalive\n\n")); err != nil {
				return
			}
			if http.NewResponseController(w).Flush() != nil {
				return
			}
		}
	}
}
