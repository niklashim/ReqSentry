package serverhealth

import (
	"sync"
	"time"

	"github.com/niklashim/ReqSentry/internal/config"
)

type Trigger struct {
	mu        sync.RWMutex
	config    config.TriggerConfig
	active    bool
	highSince time.Time
	lowSince  time.Time
}

func NewTrigger(cfg config.TriggerConfig) *Trigger {
	return &Trigger{config: cfg, active: cfg.Mode == "always"}
}

func (t *Trigger) Active() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.active
}

// Update applies sustained thresholds. Missing CPU samples reset the pending
// streak but do not turn off an already active analysis period.
func (t *Trigger) Update(at time.Time, cpu *float64) (active, changed bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.config.Mode == "always" {
		return true, false
	}
	if cpu == nil {
		t.highSince, t.lowSince = time.Time{}, time.Time{}
		return t.active, false
	}
	if !t.active {
		t.lowSince = time.Time{}
		if *cpu > t.config.CPUStart {
			if t.highSince.IsZero() {
				t.highSince = at
			}
			if at.Sub(t.highSince) >= t.config.StartDuration.Duration {
				t.active = true
				t.highSince = time.Time{}
				return true, true
			}
		} else {
			t.highSince = time.Time{}
		}
	} else {
		t.highSince = time.Time{}
		if *cpu < t.config.CPUStop {
			if t.lowSince.IsZero() {
				t.lowSince = at
			}
			if at.Sub(t.lowSince) >= t.config.StopDuration.Duration {
				t.active = false
				t.lowSince = time.Time{}
				return false, true
			}
		} else {
			t.lowSince = time.Time{}
		}
	}
	return t.active, false
}
