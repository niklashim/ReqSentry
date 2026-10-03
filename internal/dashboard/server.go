// Package dashboard serves a read-only, deny-by-default view of ReqSentry's
// existing state. It never parses access logs or makes scoring decisions.
package dashboard

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/phpfpm"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
	"github.com/niklashim/ReqSentry/internal/storage"
)

type Source interface {
	ServerName() string
	Dashboard(time.Duration, int) aggregator.DashboardView
	IPSnapshot(string, netip.Addr, time.Duration) (aggregator.Snapshot, bool)
	Enrich(netip.Addr) (enrichment.Result, error)
	Health() (serverhealth.Snapshot, bool)
	PHPFPM() []phpfpm.State
	Incidents() []model.Incident
	DeepAnalysisActive() bool
}

type State struct {
	Enabled          bool   `json:"enabled"`
	Listen           string `json:"listen,omitempty"`
	Clients          int64  `json:"clients"`
	ActiveRequests   int64  `json:"active_requests"`
	RejectedRequests uint64 `json:"rejected_requests"`
	Status           string `json:"status"`
}

const maxConcurrentRequests = 32
const maxJSONResponseBytes = 1 << 20

type Server struct {
	config      config.WebConfig
	server      *http.Server
	source      Source
	store       *storage.Store
	logger      *log.Logger
	allowed     []netip.Prefix
	trusted     []netip.Prefix
	password    string
	hub         *eventHub
	clients     atomic.Int64
	requests    chan struct{}
	active      atomic.Int64
	rejected    atomic.Uint64
	deniedIP    atomic.Uint64
	deniedAuth  atomic.Uint64
	deniedProxy atomic.Uint64
	state       atomic.Pointer[State]
	OnState     func(State)
}

func New(cfg config.WebConfig, source Source, store *storage.Store, logger *log.Logger) (*Server, error) {
	s := &Server{config: cfg, source: source, store: store, logger: logger, requests: make(chan struct{}, maxConcurrentRequests)}
	var err error
	if s.allowed, err = parseRanges(cfg.AllowedIPs); err != nil {
		return nil, fmt.Errorf("web.allowed_ips: %w", err)
	}
	if s.trusted, err = parseRanges(cfg.TrustedProxies); err != nil {
		return nil, fmt.Errorf("web.trusted_proxies: %w", err)
	}
	if cfg.Auth.Enabled {
		if cfg.Auth.Username == "" {
			return nil, errors.New("web.auth.username is required")
		}
		s.password, err = config.ResolveSecret(cfg.Auth.PasswordEnv, cfg.Auth.PasswordCredential)
		if err != nil {
			return nil, fmt.Errorf("web auth password unavailable: %w", err)
		}
	}
	address := net.JoinHostPort(cfg.Listen, strconv.Itoa(cfg.Port))
	s.server = &http.Server{Addr: address, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	s.hub = newEventHub()
	s.setState("stopped")
	return s, nil
}

func (s *Server) State() State {
	value := s.state.Load()
	if value == nil {
		return State{}
	}
	state := *value
	state.ActiveRequests = s.active.Load()
	state.RejectedRequests = s.rejected.Load()
	return state
}

func (s *Server) setState(status string) {
	state := State{Enabled: s.config.Enabled, Listen: s.server.Addr, Clients: s.clients.Load(), Status: status}
	s.state.Store(&state)
	if s.OnState != nil {
		s.OnState(state)
	}
}

func (s *Server) Run(ctx context.Context) error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		s.setState("bind_failed")
		return err
	}
	s.setState("running")
	publishCtx, stopPublisher := context.WithCancel(ctx)
	defer stopPublisher()
	if s.realtimeEnabled() {
		go s.publishLoop(publishCtx)
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.server.Shutdown(shutdown)
			cancel()
		case <-done:
		}
	}()
	err = s.server.Serve(listener)
	close(done)
	s.setState("stopped")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", s.status)
	mux.HandleFunc("/api/v1/stream", s.stream)
	mux.HandleFunc("/api/v1/", s.api)
	mux.HandleFunc("/", s.static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Second))
		peer, effective, reason := s.clientIP(r)
		if reason != "" {
			s.deny(w, r, peer, reason)
			return
		}
		if !contains(s.allowed, effective) {
			s.deny(w, r, effective, "IP_NOT_ALLOWED")
			return
		}
		if s.config.Auth.Enabled {
			username, password, ok := r.BasicAuth()
			userHash := sha256.Sum256([]byte(username))
			wantedUser := sha256.Sum256([]byte(s.config.Auth.Username))
			passHash := sha256.Sum256([]byte(password))
			wantedPass := sha256.Sum256([]byte(s.password))
			if !ok || subtle.ConstantTimeCompare(userHash[:], wantedUser[:]) != 1 || subtle.ConstantTimeCompare(passHash[:], wantedPass[:]) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="ReqSentry", charset="UTF-8"`)
				s.deny(w, r, effective, "AUTH_FAILED")
				return
			}
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
			http.Error(w, "request body not allowed", http.StatusRequestEntityTooLarge)
			return
		}
		if r.URL.Path != "/api/v1/stream" {
			select {
			case s.requests <- struct{}{}:
				s.active.Add(1)
				defer func() { s.active.Add(-1); <-s.requests }()
			default:
				s.rejected.Add(1)
				http.Error(w, "dashboard busy", http.StatusServiceUnavailable)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) (netip.Addr, netip.Addr, string) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, "INVALID_PROXY_SOURCE"
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, "INVALID_PROXY_SOURCE"
	}
	peer = peer.Unmap()
	if !contains(s.trusted, peer) {
		return peer, peer, ""
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 {
		return peer, netip.Addr{}, "INVALID_PROXY_SOURCE"
	}
	forwarded := values[0]
	if forwarded == "" || strings.Count(forwarded, ",") >= 32 {
		return peer, netip.Addr{}, "INVALID_PROXY_SOURCE"
	}
	parts := strings.Split(forwarded, ",")
	current := peer
	for i := len(parts) - 1; i >= 0 && contains(s.trusted, current); i-- {
		address, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return peer, netip.Addr{}, "INVALID_PROXY_SOURCE"
		}
		current = address.Unmap()
	}
	return peer, current, ""
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, address netip.Addr, reason string) {
	var counter *atomic.Uint64
	switch reason {
	case "AUTH_FAILED":
		counter = &s.deniedAuth
	case "INVALID_PROXY_SOURCE":
		counter = &s.deniedProxy
	default:
		counter = &s.deniedIP
	}
	count := counter.Add(1)
	if count&(count-1) == 0 && s.logger != nil {
		s.logger.Printf("dashboard access denied source=%s reason=%s count=%d", address, reason, count)
	}
	http.Error(w, "forbidden", http.StatusForbidden)
}

func parseRanges(values []string) ([]netip.Prefix, error) {
	result := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		if prefix, err := netip.ParsePrefix(value); err == nil {
			if prefix.Bits() == 0 {
				return nil, errors.New("all-address CIDR is not allowed")
			}
			if prefix.Addr().Is4In6() {
				if prefix.Bits() < 96 {
					return nil, errors.New("mapped IPv4 CIDR is too broad")
				}
				prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
			}
			result = append(result, prefix.Masked())
			continue
		}
		address, err := netip.ParseAddr(value)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", value)
		}
		address = address.Unmap()
		result = append(result, netip.PrefixFrom(address, address.BitLen()))
	}
	return result, nil
}

func contains(prefixes []netip.Prefix, address netip.Addr) bool {
	if !address.IsValid() {
		return false
	}
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func jsonResponse(w http.ResponseWriter, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "response unavailable", http.StatusInternalServerError)
		return
	}
	if len(payload)+1 > maxJSONResponseBytes {
		http.Error(w, "response too large", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_, _ = w.Write(append(payload, '\n'))
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/status" {
		http.NotFound(w, r)
		return
	}
	data := map[string]any{"web": s.State(), "mode": "monitor"}
	if s.source != nil {
		data["analysis_active"] = s.source.DeepAnalysisActive()
	}
	jsonResponse(w, data)
}
