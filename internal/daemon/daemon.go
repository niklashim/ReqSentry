// Package daemon connects log ingestion, bounded analysis, persistence, and
// optional read-only integrations for the live service.
package daemon

import (
	"context"
	"encoding/json"
	"log"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/niklashim/ReqSentry/internal/aggregator"
	"github.com/niklashim/ReqSentry/internal/clientidentity"
	"github.com/niklashim/ReqSentry/internal/config"
	"github.com/niklashim/ReqSentry/internal/correlation"
	"github.com/niklashim/ReqSentry/internal/detector"
	"github.com/niklashim/ReqSentry/internal/enrichment"
	"github.com/niklashim/ReqSentry/internal/model"
	"github.com/niklashim/ReqSentry/internal/output"
	"github.com/niklashim/ReqSentry/internal/phpfpm"
	"github.com/niklashim/ReqSentry/internal/scoring"
	"github.com/niklashim/ReqSentry/internal/serverhealth"
	"github.com/niklashim/ReqSentry/internal/storage"
	"github.com/niklashim/ReqSentry/internal/watcher"
)

type Daemon struct {
	recoveryActive           bool
	lastAnalysis             time.Time
	analysisMu               sync.Mutex
	watched                  atomic.Pointer[watcher.Manager]
	errors                   *correlation.Engine
	config                   config.Config
	logger                   *log.Logger
	health                   atomic.Pointer[serverhealth.Snapshot]
	trigger                  *serverhealth.Trigger
	phpfpm                   *phpfpm.Collector
	incidentMu               sync.RWMutex
	incidents                []model.Incident
	incidentSink             model.IncidentSink
	incidentOutputFailures   atomic.Uint64
	errorPersistenceFailures atomic.Uint64
	checkpointStore          *storage.Store
	enricher                 *enrichment.Manager
	operational              interface {
		Operational(string, string, uint64) error
	}
	notificationStatus func() []output.DeliveryStatus
	maxMindStatus      string
	slackStatus        string
	webStatus          atomic.Pointer[WebStatus]
	rollup             atomic.Pointer[aggregator.Aggregator]
}

type WebStatus struct {
	Enabled bool   `json:"enabled"`
	Listen  string `json:"listen,omitempty"`
	Clients int64  `json:"clients"`
	Status  string `json:"status"`
}

type Status struct {
	Recovery      RecoveryStatus          `json:"recovery"`
	Storage       storage.RetentionStatus `json:"storage"`
	Notifications []output.DeliveryStatus `json:"notifications,omitempty"`
	UpdatedAt     time.Time               `json:"updated_at"`
	Running       bool                    `json:"running"`
	TriggerActive bool                    `json:"trigger_active"`
	Health        serverhealth.Snapshot   `json:"health"`
	WatchedLogs   []watcher.Status        `json:"watched_logs"`
	Aggregation   aggregator.Metrics      `json:"aggregation"`
	SQLite        string                  `json:"sqlite"`
	MaxMind       string                  `json:"maxmind"`
	Slack         string                  `json:"slack"`
	Web           WebStatus               `json:"web"`
}

func New(cfg config.Config, logger *log.Logger) *Daemon {
	d := &Daemon{errors: correlation.New(cfg.Correlation, len(cfg.ErrorFiles) > 0), config: cfg, logger: logger, trigger: serverhealth.NewTrigger(cfg.Trigger)}
	if cfg.PHPFPM.Enabled {
		d.phpfpm = phpfpm.New(cfg.PHPFPM)
	}
	return d
}

func (d *Daemon) Health() (serverhealth.Snapshot, bool) {
	value := d.health.Load()
	if value == nil {
		return serverhealth.Snapshot{}, false
	}
	return *value, true
}

func (d *Daemon) DeepAnalysisActive() bool {
	return d.trigger.Active()
}

func (d *Daemon) PHPFPM() []phpfpm.State {
	if d.phpfpm == nil {
		return nil
	}
	return d.phpfpm.States(time.Now())
}

func (d *Daemon) Incidents() []model.Incident {
	d.incidentMu.RLock()
	defer d.incidentMu.RUnlock()
	return append([]model.Incident(nil), d.incidents...)
}

func (d *Daemon) ServerName() string { return d.config.Server.Name }

func (d *Daemon) Enrich(ip netip.Addr) (enrichment.Result, error) {
	if d.enricher == nil {
		return enrichment.Result{}, nil
	}
	return d.enricher.Lookup(ip)
}

func (d *Daemon) Dashboard(window time.Duration, limit int) aggregator.DashboardView {
	rollup := d.rollup.Load()
	if rollup == nil {
		return aggregator.DashboardView{At: time.Now(), Sites: []aggregator.DashboardSite{}}
	}
	view := rollup.Dashboard(window, time.Now(), limit)
	known := make(map[string]bool, len(view.Sites))
	for _, site := range view.Sites {
		known[site.SiteID] = true
	}
	for _, file := range d.config.AccessFiles {
		if !known[file.Site] {
			view.Sites = append(view.Sites, aggregator.DashboardSite{SiteID: file.Site, Statuses: map[int]uint64{}, Methods: map[string]uint64{}})
			known[file.Site] = true
		}
	}
	incidents := d.Incidents()
	cutoff := time.Now().Add(-5 * time.Minute)
	type siteIncidentSummary struct {
		count      int
		suspicious map[netip.Addr]bool
		wouldBlock map[netip.Addr]bool
	}
	bySite := make(map[string]*siteIncidentSummary)
	for _, incident := range incidents {
		if incident.Timestamp.Before(cutoff) {
			continue
		}
		item := bySite[incident.SiteID]
		if item == nil {
			item = &siteIncidentSummary{suspicious: make(map[netip.Addr]bool), wouldBlock: make(map[netip.Addr]bool)}
			bySite[incident.SiteID] = item
		}
		item.count++
		if incident.Decision == model.DecisionSuspicious || incident.Decision == model.DecisionWouldBlock {
			item.suspicious[incident.ClientIP] = true
		}
		if incident.Decision == model.DecisionWouldBlock {
			item.wouldBlock[incident.ClientIP] = true
		}
	}
	for i := range view.Sites {
		if item := bySite[view.Sites[i].SiteID]; item != nil {
			view.Sites[i].RecentIncidents = item.count
			view.Sites[i].SuspiciousIPs = len(item.suspicious)
			view.Sites[i].WouldBlockIPs = len(item.wouldBlock)
		}
	}
	sort.Slice(view.Sites, func(i, j int) bool { return view.Sites[i].SiteID < view.Sites[j].SiteID })
	return view
}

func (d *Daemon) IPSnapshot(site string, ip netip.Addr, window time.Duration) (aggregator.Snapshot, bool) {
	rollup := d.rollup.Load()
	if rollup == nil {
		return aggregator.Snapshot{}, false
	}
	return rollup.Snapshot(site, ip, window, time.Now())
}

func (d *Daemon) SetIncidentSink(sink model.IncidentSink) {
	d.incidentSink = sink
}

func (d *Daemon) SetCheckpointStore(store *storage.Store) {
	d.checkpointStore = store
}

func (d *Daemon) SetEnricher(manager *enrichment.Manager) {
	d.enricher = manager
}

func (d *Daemon) SetIntegrationStatus(maxmind, slack string) {
	d.maxMindStatus = maxmind
	d.slackStatus = slack
}

func (d *Daemon) SetWebStatus(status WebStatus) { d.webStatus.Store(&status) }

func (d *Daemon) SetOperationalSink(sink interface {
	Operational(string, string, uint64) error
}) {
	d.operational = sink
}

func (d *Daemon) alert(kind, detail string, failures uint64) {
	if d.operational != nil {
		if err := d.operational.Operational(kind, detail, failures); err != nil {
			d.logger.Printf("operational alert queue failed: %v", err)
		}
	}
}

// Run ingests access logs and produces monitor-only incident decisions.
func (d *Daemon) Run(ctx context.Context) error {
	d.logger.Printf("ReqSentry starting server=%s mode=%s logs=%d", d.config.Server.Name, d.config.Mode, len(d.config.AccessFiles))
	var parsed atomic.Uint64
	var allowlisted atomic.Uint64
	resolver, err := clientidentity.New(d.config)
	if err != nil {
		return err
	}
	scorer, err := scoring.New(d.config.Detection)
	if err != nil {
		return err
	}
	rollup := aggregator.New(d.config.Aggregation, d.config.Analysis.Window.Duration)
	d.rollup.Store(rollup)
	recoveryStatus := RecoveryStatus{Enabled: d.config.Recovery.Enabled, State: "disabled"}
	var resume map[string]storage.Offset
	if d.config.Recovery.Enabled && d.checkpointStore != nil {
		recoveryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		var recoveryErr error
		resume, recoveryStatus, recoveryErr = d.recover(recoveryCtx, rollup)
		cancel()
		if recoveryErr != nil {
			rollup = aggregator.New(d.config.Aggregation, d.config.Analysis.Window.Duration)
			d.rollup.Store(rollup)
			d.errors.Reset()
			recoveryStatus.State = "deferred"
			recoveryStatus.Detail = recoveryErr.Error()
			d.logger.Printf("crash recovery deferred: %s", recoveryStatus.Detail)
		} else {
			d.recoveryActive = true
		}
	}
	if d.config.Recovery.Enabled && d.checkpointStore == nil {
		recoveryStatus.State = "unavailable"
		recoveryStatus.Detail = "SQLite unavailable"
	}

	historyDone := make(chan struct{})
	if d.checkpointStore != nil && d.config.Web.Enabled {
		go func() { defer close(historyDone); d.monitorDashboardHistory(ctx, rollup) }()
	} else {
		close(historyDone)
	}
	allSources := append(append([]config.AccessFile(nil), d.config.AccessFiles...), d.config.ErrorFiles...)
	manager := watcher.New(allSources, d.logger, func(event model.RequestEvent) {
		parsed.Add(1)
		resolved, excluded := resolver.Resolve(event)
		if excluded {
			allowlisted.Add(1)
		}
		at := time.Now()
		if d.recoveryActive {
			at = resolved.Timestamp
		}
		rollup.Observe(resolved, excluded, at)
		d.errors.Observe(resolved)
	})
	manager.SetResumeOffsets(resume)
	d.watched.Store(manager)
	manager.SetProfiles(d.config.LogProfiles)
	manager.SetErrorSink(func(event model.ErrorEvent) {
		d.errors.ObserveError(event)
		if d.checkpointStore != nil {
			if err := d.checkpointStore.WriteError(event); err != nil {
				count := d.errorPersistenceFailures.Add(1)
				d.errors.MarkDropped()
				if count&(count-1) == 0 {
					d.logger.Printf("error evidence dropped count=%d", count)
				}
			}
		}
	})
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		consecutive := make(map[string]uint64)
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				for _, status := range manager.Status() {
					if status.LastError != "" {
						consecutive[status.Path]++
						d.alert("input:"+status.Site, status.LastError, consecutive[status.Path])
					} else {
						consecutive[status.Path] = 0
					}
				}
			}
		}
	}()
	if d.checkpointStore != nil {
		manager.SetCheckpointStore(d.checkpointStore)
	}
	checkpointDone := make(chan struct{})
	if d.recoveryActive {
		lookback := 2 * d.config.Analysis.Window.Duration
		manager.ConfigureRecovery(lookback, d.config.Recovery.MaxBytes)
		go func() {
			defer close(checkpointDone)
			manager.PeriodicCheckpoints(ctx, d.config.Recovery.Interval.Duration, lookback, d.config.Recovery.MaxBytes)
		}()
	} else {
		close(checkpointDone)
	}
	statusDone := make(chan struct{})
	go func() {
		defer close(statusDone)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		lowDiskCount := uint64(0)
		write := func(running bool) {
			if d.checkpointStore == nil {
				return
			}
			health, _ := d.Health()
			maxmindStatus := d.maxMindStatus
			if d.enricher != nil && d.enricher.Available() {
				maxmindStatus = "available"
			}
			if maxmindStatus == "" {
				maxmindStatus = "disabled"
			}
			slackStatus := d.slackStatus
			if slackStatus == "" {
				slackStatus = "disabled"
			}
			status := Status{Recovery: recoveryStatus, UpdatedAt: time.Now().UTC(), Running: running, TriggerActive: d.trigger.Active(), Health: health, WatchedLogs: manager.Status(), Aggregation: rollup.Metrics(), SQLite: "available", MaxMind: maxmindStatus, Slack: slackStatus}
			if d.notificationStatus != nil {
				status.Notifications = d.notificationStatus()
			}
			if web := d.webStatus.Load(); web != nil {
				status.Web = *web
			}
			diskCtx, diskCancel := context.WithTimeout(context.Background(), time.Second)
			status.Storage = d.checkpointStore.DiskStatus(diskCtx, d.config.Database.Retention.MinimumFreeBytes)
			diskCancel()
			if status.Storage.LowDisk {
				lowDiskCount++
				if lowDiskCount&(lowDiskCount-1) == 0 {
					d.logger.Printf("storage low disk free_bytes=%d", status.Storage.FreeBytes)
				}
				d.alert("storage_low_disk", "configured disk threshold reached", lowDiskCount)
			} else {
				lowDiskCount = 0
			}
			payload, _ := json.Marshal(status)
			writeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := d.checkpointStore.SetState(writeCtx, "daemon.status", string(payload)); err != nil {
				d.logger.Printf("daemon status update failed: %v", err)
			}
		}
		write(true)
		for {
			select {
			case <-ctx.Done():
				write(false)
				return
			case <-ticker.C:
				write(true)
			}
		}
	}()
	pruneDone := make(chan struct{})
	go func() {
		defer close(pruneDone)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				rollup.Prune(now)
				d.errors.Prune(now)
				var memory runtime.MemStats
				runtime.ReadMemStats(&memory)
				degraded := rollup.Metrics().Degraded
				if !degraded && d.config.Aggregation.DegradeAtBytes > 0 && int64(memory.HeapAlloc) >= d.config.Aggregation.DegradeAtBytes {
					if rollup.SetDegraded(true) {
						d.logger.Printf("aggregation degraded heap_bytes=%d threshold=%d", memory.HeapAlloc, d.config.Aggregation.DegradeAtBytes)
					}
				} else if degraded && int64(memory.HeapAlloc) <= d.config.Aggregation.RecoverBelowBytes {
					if rollup.SetDegraded(false) {
						d.logger.Printf("aggregation recovered heap_bytes=%d threshold=%d", memory.HeapAlloc, d.config.Aggregation.RecoverBelowBytes)
					}
				}
			}
		}
	}()
	healthDone := make(chan struct{})
	analysisWake := make(chan struct{}, 1)
	go func() {
		defer close(healthDone)
		d.monitorHealth(ctx, analysisWake)
	}()
	analysisDone := make(chan struct{})
	go func() {
		defer close(analysisDone)
		d.monitorAnalysis(ctx, rollup, scorer, analysisWake)
	}()
	manager.SetAfterDrain(func() bool {
		<-analysisDone
		if d.trigger.Active() {
			d.analyzeOnce(rollup, scorer, time.Now())
		}
		if d.checkpointStore != nil {
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := d.checkpointStore.Flush(flushCtx); err != nil {
				d.logger.Printf("SQLite flush failed; watcher offsets remain at prior checkpoint: %v", err)
				return false
			}
		}
		return true
	})
	phpDone := make(chan struct{})
	if d.phpfpm != nil {
		defer d.phpfpm.Close()
		go func() {
			defer close(phpDone)
			d.monitorPHPFPM(ctx)
		}()
	} else {
		close(phpDone)
	}
	d.logger.Print("ingesting and analyzing access logs in monitor mode")
	manager.Run(ctx)
	<-pruneDone
	<-healthDone
	<-analysisDone
	<-phpDone
	<-watchDone
	<-statusDone
	<-historyDone
	<-checkpointDone
	metrics := rollup.Metrics()
	d.logger.Printf("ReqSentry stopped parsed_requests=%d allowlisted_requests=%d active_records=%d dropped_events=%d", parsed.Load(), allowlisted.Load(), metrics.ActiveRecords, metrics.DroppedEvents)
	return nil
}

func (d *Daemon) monitorPHPFPM(ctx context.Context) {
	ticker := time.NewTicker(d.config.PHPFPM.Interval.Duration)
	defer ticker.Stop()
	failures := make(map[string]uint64)
	for {
		states := d.phpfpm.Poll(ctx, time.Now())
		for _, state := range states {
			if state.LastError != "" {
				failures[state.Name]++
				count := failures[state.Name]
				if count&(count-1) == 0 {
					d.logger.Printf("PHP-FPM status unavailable pool=%s failures=%d: %s", state.Name, count, state.LastError)
				}
				d.alert("php_fpm:"+state.Name, state.LastError, count)
			} else if failures[state.Name] > 0 {
				d.logger.Printf("PHP-FPM status recovered pool=%s", state.Name)
				failures[state.Name] = 0
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) monitorHealth(ctx context.Context, analysisWake chan<- struct{}) {
	interval := d.config.Health.Interval.Duration
	if interval <= 0 {
		interval = time.Second
	}
	sampler := serverhealth.NewProcSampler("/proc")
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var failures uint64
	for {
		now := time.Now()
		snapshot, err := sampler.Sample(now)
		d.health.Store(&snapshot)
		if err != nil {
			failures++
			if failures&(failures-1) == 0 {
				d.logger.Printf("server health unavailable failures=%d: %v", failures, err)
			}
			d.alert("server_health", err.Error(), failures)
		} else if failures > 0 {
			d.logger.Print("server health sampling recovered")
			failures = 0
		}
		if active, changed := d.trigger.Update(now, snapshot.CPUPercent); changed {
			d.logger.Printf("deep analysis active=%t cpu=%.1f%%", active, *snapshot.CPUPercent)
			if active {
				select {
				case analysisWake <- struct{}{}:
				default:
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *Daemon) monitorAnalysis(ctx context.Context, rollup *aggregator.Aggregator, scorer *scoring.Engine, wake <-chan struct{}) {
	window := d.config.Analysis.Window.Duration
	if window <= 0 {
		window = 30 * time.Second
	}
	next := time.Now().Truncate(window).Add(window)
	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	if d.trigger.Active() {
		d.analyzeOnce(rollup, scorer, time.Now())
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			if d.trigger.Active() {
				d.analyzeClosedWindow(rollup, scorer, next)
			}
			next = time.Now().Truncate(window).Add(window)
			timer.Reset(time.Until(next))
		case <-wake:
			if d.trigger.Active() {
				d.analyzeOnce(rollup, scorer, time.Now())
			}
		}
	}

}

// A scheduled tick belongs to the window that just ended, not the newly
// opened second. Using an inclusive new-second endpoint would miss the first
// second of each completed window. Startup/trigger/shutdown may still request
// a rolling partial window through analyzeOnce.
func (d *Daemon) analyzeClosedWindow(rollup *aggregator.Aggregator, scorer *scoring.Engine, at time.Time) {
	if !d.recoveryActive {
		window := d.config.Analysis.Window.Duration
		if window <= 0 {
			window = 30 * time.Second
		}
		at = at.Truncate(window).Add(-time.Nanosecond)
	}
	d.analyzeOnce(rollup, scorer, at)
}

func (d *Daemon) analyzeOnce(rollup *aggregator.Aggregator, scorer *scoring.Engine, now time.Time) {
	d.analysisMu.Lock()
	defer d.analysisMu.Unlock()
	if d.recoveryActive {
		now = now.Truncate(d.config.Analysis.Window.Duration).Add(-time.Nanosecond)
		if !now.After(d.lastAnalysis) {
			return
		}
		d.lastAnalysis = now
	}

	window := d.config.Analysis.Window.Duration
	if window <= 0 {
		window = 30 * time.Second
	}
	allRequests := rollup.TotalRequests(window, now)
	health, _ := d.Health()
	pools := d.PHPFPM()
	for snapshot, siteCount := range rollup.AnalysisSnapshots(window, now) {
		signals := detector.HTTPWithRules(snapshot, d.config.Detection)
		if snapshot.SiteID == "" {
			signals = append(signals, detector.ImpactWithRules(snapshot, allRequests,
				siteCount, health, pools, d.config.Detection)...)
		}
		if len(signals) == 0 {
			continue
		}
		status := "disabled"
		var enrichmentResult enrichment.Result
		if d.enricher != nil {
			var lookupErr error
			enrichmentResult, lookupErr = d.enricher.Lookup(snapshot.ClientIP)
			switch {
			case lookupErr != nil:
				status = "lookup_error"
				d.logger.Printf("MaxMind lookup failed ip=%s: %v", snapshot.ClientIP, lookupErr)
			case !enrichmentResult.Available:
				status = "unavailable"
			case !enrichmentResult.Found:
				status = "not_found"
			default:
				status = "available"
				if strings.EqualFold(enrichmentResult.NetworkType, "hosting") {
					signals = append(signals, model.Signal{Code: "HOSTING_NETWORK", Strength: model.SignalSupporting,
						Evidence: map[string]any{"network_type": enrichmentResult.NetworkType}})
				}
			}
		}
		incident := scorer.Evaluate(scoring.Input{
			Server: d.config.Server.Name, Snapshot: snapshot, Signals: signals,
			AllRequests: allRequests, Health: health, PHPFPM: pools,
		})
		incident.Errors = d.errors.Context(incident)
		for _, source := range d.ErrorSources() {
			if !source.Open || source.LastError != "" {
				incident.Errors.UnavailableSources = append(incident.Errors.UnavailableSources, source.Path)
			}
		}
		incident.EnrichmentStatus = status
		incident.ASN = enrichmentResult.ASN
		incident.ASNOrganization = enrichmentResult.ASNOrganization
		incident.ISP = enrichmentResult.ISP
		incident.NetworkType = enrichmentResult.NetworkType
		incident.Country = enrichmentResult.Country
		if incident.Decision == model.DecisionNormal {
			continue
		}
		d.incidentMu.Lock()
		if len(d.incidents) == 100 {
			d.incidents = d.incidents[1:]
		}
		d.incidents = append(d.incidents, incident)
		d.incidentMu.Unlock()
		if d.incidentSink != nil {
			if err := d.incidentSink.WriteIncident(context.Background(), incident); err != nil {
				failures := d.incidentOutputFailures.Add(1)
				if failures&(failures-1) == 0 {
					d.logger.Printf("incident output failed failures=%d: %v", failures, err)
				}
				d.alert("incident_output", err.Error(), failures)
			}
		}
		codes := make([]string, 0, len(incident.Signals))
		for _, signal := range incident.Signals {
			codes = append(codes, signal.Code)
		}
		d.logger.Printf("incident site=%s ip=%s score=%d decision=%s ruleset=%d reasons=%s MONITOR MODE - NO ACTION TAKEN",
			incident.SiteID, incident.ClientIP, incident.Score, incident.Decision, incident.RulesetVersion, strings.Join(codes, ","))
	}
}

func (d *Daemon) SetNotificationStatus(f func() []output.DeliveryStatus) { d.notificationStatus = f }

func (d *Daemon) RecentErrors(site string, from, to time.Time, limit int) []model.ErrorEvent {
	return d.errors.Recent(site, from, to, limit)
}

func (d *Daemon) ErrorSources() []watcher.Status {
	out := []watcher.Status{}
	if m := d.watched.Load(); m != nil {
		for _, s := range m.Status() {
			if s.Kind == "error" {
				out = append(out, s)
			}
		}
	}
	return out
}
