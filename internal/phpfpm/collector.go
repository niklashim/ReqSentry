// Package phpfpm polls a locally exposed PHP-FPM JSON status page. It never
// runs on the access-log request path.
package phpfpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
)

const maxStatusBytes = 64 << 10

type Stats struct {
	Pool               string `json:"pool"`
	ActiveProcesses    *int64 `json:"active processes"`
	IdleProcesses      *int64 `json:"idle processes"`
	TotalProcesses     *int64 `json:"total processes"`
	MaxActiveProcesses *int64 `json:"max active processes"`
	MaxChildrenReached *int64 `json:"max children reached"`
	SlowRequests       *int64 `json:"slow requests"`
	ListenQueue        *int64 `json:"listen queue"`
}

type State struct {
	Name      string
	SampledAt time.Time
	Stats     *Stats
	Stale     bool
	LastError string
}

type Collector struct {
	config config.PHPFPMConfig
	client *http.Client
	mu     sync.RWMutex
	states map[string]State
	pollMu sync.Mutex
	now    func() time.Time
}

func New(cfg config.PHPFPMConfig) *Collector {
	return &Collector{
		config: cfg, now: time.Now, client: &http.Client{
			Timeout:       2 * time.Second,
			Transport:     &http.Transport{Proxy: nil},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		states: make(map[string]State),
	}
}

func (c *Collector) Close() {
	c.client.CloseIdleConnections()
}

// Poll keeps the last good sample on failure and records the failure as stale.
// One failed pool does not prevent other pools from being sampled.
func (c *Collector) Poll(ctx context.Context, _ time.Time) []State {
	c.pollMu.Lock()
	defer c.pollMu.Unlock()
	budget := 2 * time.Second
	if interval := c.config.Interval.Duration; interval > 0 && interval < budget {
		budget = interval
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	jobs := make(chan config.PHPFPMPoolConfig)
	var workers sync.WaitGroup
	// Configuration admits at most sixteen pools. Start one bounded worker per
	// pool so a healthy endpoint never waits behind failed endpoints.
	for range min(16, len(c.config.Pools)) {
		workers.Go(func() {
			for pool := range jobs {
				stats, err := c.fetch(ctx, pool.StatusURL)
				sampledAt := c.now()
				c.mu.Lock()
				state := c.states[pool.Name]
				state.Name = pool.Name
				if err != nil {
					state.LastError = err.Error()
					state.Stale = true
				} else {
					state.SampledAt = sampledAt
					state.Stats = &stats
					state.LastError = ""
					state.Stale = false
				}
				c.states[pool.Name] = state
				c.mu.Unlock()
			}
		})
	}
enqueue:
	for _, pool := range c.config.Pools {
		select {
		case jobs <- pool:
		case <-ctx.Done():
			break enqueue
		}
	}
	close(jobs)
	workers.Wait()
	return c.States(c.now())
}

func (c *Collector) States(now time.Time) []State {
	c.mu.RLock()
	defer c.mu.RUnlock()
	states := make([]State, 0, len(c.config.Pools))
	for _, pool := range c.config.Pools {
		state := c.states[pool.Name]
		state.Name = pool.Name
		if state.SampledAt.IsZero() || now.Sub(state.SampledAt) > 2*c.config.Interval.Duration {
			state.Stale = true
		}
		states = append(states, state)
	}
	return states
}

func (c *Collector) fetch(ctx context.Context, address string) (Stats, error) {
	u, err := url.Parse(address)
	if err != nil {
		return Stats{}, err
	}
	if !u.Query().Has("json") {
		if u.RawQuery == "" {
			u.RawQuery = "json"
		} else {
			u.RawQuery += "&json"
		}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return Stats{}, err
	}
	response, err := c.client.Do(request)
	if err != nil {
		return Stats{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Stats{}, fmt.Errorf("PHP-FPM status HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxStatusBytes+1))
	if err != nil {
		return Stats{}, err
	}
	if len(body) > maxStatusBytes {
		return Stats{}, errors.New("PHP-FPM status response exceeds 64 KiB")
	}
	var stats Stats
	if err := json.Unmarshal(body, &stats); err != nil {
		return Stats{}, errors.New("invalid PHP-FPM status JSON")
	}
	if stats.ActiveProcesses == nil || stats.IdleProcesses == nil || stats.TotalProcesses == nil {
		return Stats{}, errors.New("PHP-FPM status is missing process counts")
	}
	for _, value := range []*int64{stats.ActiveProcesses, stats.IdleProcesses, stats.TotalProcesses, stats.MaxActiveProcesses, stats.MaxChildrenReached, stats.SlowRequests, stats.ListenQueue} {
		if value != nil && *value < 0 {
			return Stats{}, errors.New("PHP-FPM status has a negative counter")
		}
	}
	return stats, nil
}
